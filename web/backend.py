"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

FastAPI backend for BACnet Security Monitoring Web GUI.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import json
from pathlib import Path
import sys
import yaml
from datetime import datetime
from contextlib import asynccontextmanager

# Import agent components
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
from google.adk.agents.run_config import RunConfig, StreamingMode

# Import MCP Client
from fastmcp import Client
from mcp.types import GetTaskResult

# Add parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bacnet.anomaly_storage import AnomalyStorage
from bacnet.pcap_monitor import PCAPMonitor

# Config path
AGENT_CONFIG_PATH = Path(__file__).parent / "config" / "agent.yaml"

# Global instances
storage = AnomalyStorage()
pcap_monitor = None
anomaly_event = None
websocket_clients = []
agent_lock = asyncio.Lock()
mcp_client = None
mcp_tasks = []

# Agent service (will be initialized if available)
agent_service = None
# Create session service
session_service = InMemorySessionService()


def load_agent_config(config_path: Path = AGENT_CONFIG_PATH) -> dict:
    """Load agent configuration from YAML file."""
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        if config is None:
            config = {}
        print(f"[✓] Agent config loaded from {config_path}")
        return config
    except FileNotFoundError:
        print(f"[!] Config file not found: {config_path}. Using defaults.")
        return {}
    except yaml.YAMLError as e:
        print(f"[!] Error parsing config file: {e}. Using defaults.")
        return {}


class QueryRequest(BaseModel):
    query: str


class QueryResponse(BaseModel):
    response: str
    timestamp: str


# Create agent service wrapper
class AgentService:
    def __init__(self, runner):
        self.runner = runner

    async def process_query(self, query: str, session_id: str = "chat_session"):
        """Process a user query (non-streaming, used internally for anomaly handling)."""
        content = types.Content(role='user', parts=[types.Part(text=query)])

        final_response_text = "I apologize, but I couldn't process your request."
        tool_was_called = False

        async for event in self.runner.run_async(
            user_id="web_user",
            session_id=session_id,
            new_message=content
        ):
            # Detect MCP tool calls in event parts
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if getattr(part, "function_call", None):
                        tool_was_called = True

            if event.is_final_response():
                if event.content and event.content.parts:
                    final_response_text = event.content.parts[0].text
                break

        # Clean history to avoid large system prompts after tool calls
        if tool_was_called:
            print(f"[*] MCP tool call detected in session '{session_id}', cleaning history...")
            await session_service.delete_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )
            await session_service.create_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )

        return final_response_text

    async def process_query_stream(self, query: str, session_id: str = "chat_session"):
        """Process a user query and yield SSE events for tool calls, text chunks, and final response."""
        content = types.Content(role='user', parts=[types.Part(text=query)])

        accumulated_text = ""
        tool_was_called = False

        async for event in self.runner.run_async(
            user_id="web_user",
            session_id=session_id,
            new_message=content,
            run_config=RunConfig(
                streaming_mode=StreamingMode.SSE,
            )
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    # Detect and stream tool calls
                    if getattr(part, "function_call", None):
                        tool_was_called = True
                        fc = part.function_call
                        try:
                            tool_args = dict(fc.args) if fc.args else {}
                        except Exception:
                            tool_args = {}
                        yield f"data: {json.dumps({'type': 'tool_call', 'tool_name': fc.name, 'tool_args': tool_args}, default=str)}\n\n"

                    # Detect and stream tool responses
                    elif getattr(part, "function_response", None):
                        fr = part.function_response
                        yield f"data: {json.dumps({'type': 'tool_response', 'tool_name': fr.name})}\n\n"

                    # Stream partial text chunks as they arrive
                    elif getattr(part, "text", None):
                        chunk = part.text
                        accumulated_text += chunk
                        yield f"data: {json.dumps({'type': 'text_chunk', 'text': chunk})}\n\n"

            if event.is_final_response():
                # If we never streamed any text, grab it from the final event
                if not accumulated_text and event.content and event.content.parts:
                    final_text = event.content.parts[0].text
                    if final_text:
                        accumulated_text = final_text
                        yield f"data: {json.dumps({'type': 'text_chunk', 'text': final_text})}\n\n"
                break

        # Clean history to avoid large system prompts after tool calls
        if tool_was_called:
            print(f"[*] MCP tool call detected in session '{session_id}', cleaning history...")
            await session_service.delete_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )
            await session_service.create_session(
                app_name="bacnet_security_app",
                user_id="web_user",
                session_id=session_id
            )

        final_response_text = accumulated_text or "I apologize, but I couldn't process your request."
        yield f"data: {json.dumps({'type': 'final_response', 'response': final_response_text})}\n\n"

async def on_status_change_cb(status: GetTaskResult) -> None:
    """Callback for MCP task status changes (triggered by anomaly detection)."""
    if status.statusMessage:
        print(f"[*] Task status update: {status.statusMessage}")
        
        # Parse the anomaly data from status message
        anomaly_data = {
            "anomaly_type": "MCP_DETECTED",
            "severity": "medium",
            "description": status.statusMessage,
            "timestamp": datetime.now().isoformat()
        }
        
        # Get agent analysis if available
        message = None
        if agent_service:
            try:
                async with agent_lock:
                    query = f"A task status update was received: {status}. Please report this anomaly politely to the user"
                    analysis_text = await agent_service.process_query(query, session_id="anomaly_session")
                    
                    message = {
                        "type": "anomaly",
                        "data": {
                            "anomaly": anomaly_data,
                            "analysis": analysis_text
                        }
                    }
            except Exception as e:
                print(f"[!] Error getting agent analysis: {e}")
                message = {
                    "type": "anomaly",
                    "data": {"anomaly": anomaly_data}
                }
        else:
            message = {
                "type": "anomaly",
                "data": {"anomaly": anomaly_data}
            }
        
        # Broadcast to all connected WebSocket clients
        if message:
            disconnected = []
            for client in websocket_clients:
                try:
                    await client.send_json(message)
                except:
                    disconnected.append(client)
            
            # Remove disconnected clients
            for client in disconnected:
                websocket_clients.remove(client)

    # Define after_tool_callback to remove content field
async def after_tool_callback(tool: str, args: dict, tool_context: str, tool_response: dict) -> dict:
    """
    Callback to process tool results before sending to LLM.
    Removes the 'content' field to reduce payload size.
    """
    if isinstance(tool_response, dict) and "content" in tool_response:
        # Create a copy without the content field
        filtered_result = {k: v for k, v in tool_response.items() if k != "content"}
        print(f"[*] Removed 'content' field from {tool} result (reduced payload)")
        return filtered_result
    return tool_response

async def initialize_agent():
    """Initialize the AI agent service with MCP Client."""
    global agent_service, mcp_client, mcp_tasks
    
    # Load agent configuration from YAML
    agent_config = load_agent_config()
    system_prompt = agent_config.get("system_prompt", "")

    if not system_prompt:
        print("[!] No system_prompt found in config. Using default instruction.")
        system_prompt = (
            "You are a BACnet network security expert. "
            "Monitor the network for anomalies, analyze device behavior, "
            "and provide security recommendations. "
            "Use the available tools to query devices, anomalies, and statistics. "
            "Present information clearly and highlight critical security issues."
        )
    else:
        print(f"[✓] Loaded system_prompt from config ({len(system_prompt)} chars)")

    try:
        print("[*] Connecting to MCP Server...")
        mcp_client = Client("http://localhost:8081/mcp")
        await mcp_client.__aenter__()
        
        # List and filter tools
        tools = await mcp_client.list_tools()
        trigger_tools = []
        allowed_tools = []
        
        for tool in tools:
            if "trigger" in tool.meta.get("fastmcp", {}).get("tags", []):
                trigger_tools.append(tool.name)
            else:
                allowed_tools.append(tool.name)
        
        print(f"[*] Available tools: {[tool.name for tool in tools]}")
        print(f"[*] Trigger tools: {trigger_tools}")
        print(f"[*] Allowed tools: {allowed_tools}")
        
        # Launch trigger tools as tasks
        for tool_name in trigger_tools:
            task = await mcp_client.call_tool(tool_name, task=True)
            task.on_status_change(on_status_change_cb)
            mcp_tasks.append(task)
            print(f"[*] Started trigger task: {task.task_id}")
        
        # Create agent with system_prompt from config and after_tool_callback
        agent = Agent(
            name="bacnet_security_agent",
            model=LiteLlm(
                model="openai/Qwen2.5-7B-Instruct",
                api_base="http://0.0.0.0:8000/v1",
                api_key="sk-no-required"
            ),
            description="BACnet anomaly detection assistant.",
            instruction=system_prompt,
            tools=[
                McpToolset(
                    connection_params=StreamableHTTPConnectionParams(url="http://localhost:8081/mcp"),
                    tool_filter=allowed_tools,  # Only use allowed tools, not trigger tools
                )
            ],
            after_tool_callback=after_tool_callback  # Add callback to filter results
        )

        await session_service.create_session(
            app_name="bacnet_security_app",
            user_id="web_user",
            session_id="chat_session"
        )
        await session_service.create_session(
            app_name="bacnet_security_app",
            user_id="web_user",
            session_id="anomaly_session"
        )
        
        # Create runner
        runner = Runner(
            agent=agent,
            app_name="bacnet_security_app",
            session_service=session_service
        )
        
        agent_service = AgentService(runner)
        
        # Run first query as set up 
        async with agent_lock:
            await agent_service.process_query("Hi",session_id="chat_session")
            
        print("[✓] AI Agent initialized successfully")
        return True
        
    except Exception as e:
        print(f"[!] Could not initialize AI Agent: {e}")
        print("[*] Agent features will be disabled")
        import traceback
        traceback.print_exc()
        return False

async def broadcast_anomalies():
    """Continuously broadcast anomaly notifications from PCAP monitor to WebSocket clients."""
    while True:
        try:
            anomaly = await anomaly_event.wait_for_anomaly()
            
            """
            # Get agent analysis if available
            if agent_service:
                try:
                    async with agent_lock:
                        analysis = await agent_service.handle_anomaly_notification(anomaly)
                        message = {
                            "type": "anomaly",
                            "data": analysis
                        }
                except Exception as e:
                    print(f"[!] Error getting agent analysis: {e}")
                    message = {
                        "type": "anomaly",
                        "data": {"anomaly": anomaly}
                    }
            else:
                message = {
                    "type": "anomaly",
                    "data": {"anomaly": anomaly}
                }
            """
            message = {
                "type": "anomaly",
                "data": {"anomaly": anomaly}
            }
            
            # Broadcast to all connected clients
            disconnected = []
            for client in websocket_clients:
                try:
                    await client.send_json(message)
                except:
                    disconnected.append(client)
            
            # Remove disconnected clients
            for client in disconnected:
                websocket_clients.remove(client)
        
        except Exception as e:
            print(f"[!] Error broadcasting anomaly: {e}")
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown."""
    global pcap_monitor, anomaly_event
    
    # Startup
    print("=" * 60)
    print("BACnet Security Monitor - Backend Starting")
    print("=" * 60)
    print()
    
    # Create directories
    Path("pcap_files").mkdir(exist_ok=True)
    Path("web/static").mkdir(exist_ok=True)
    
    # Initialize AI agent with MCP Client
    print("[1/3] Initializing AI Agent with MCP Client...")
    await initialize_agent()
    # Start PCAP monitor with shared anomaly event from MCP server
    print("[2/3] Starting PCAP Monitor...")
    
    pcap_monitor = PCAPMonitor(pcap_directory="./pcap_files", poll_interval=60)
    anomaly_event = pcap_monitor.anomaly_event   # Share the same event instance
    
    asyncio.create_task(pcap_monitor.start())
    
    # Start anomaly notification broadcaster
    print("[3/3] Starting WebSocket Broadcaster...")
    # Broadcast will be handle by Agent callback 
    asyncio.create_task(broadcast_anomalies())
    
    yield
    
    # Shutdown
    if pcap_monitor:
        pcap_monitor.stop()
    
    if mcp_client:
        await mcp_client.__aexit__(None, None, None)



app = FastAPI(
    title="NXP Agentic AI Network Monitoring System",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    websocket_clients.append(websocket)
    print(f"[*] WebSocket client connected. Total clients: {len(websocket_clients)}")
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        websocket_clients.remove(websocket)
        print(f"[*] WebSocket client disconnected. Total clients: {len(websocket_clients)}")


@app.get("/api/devices")
async def get_devices():
    """Get all discovered BACnet devices."""
    devices = storage.get_all_devices()
    return {"status": "success", "devices": devices}


@app.get("/api/anomalies")
async def get_anomalies(limit: int = 50, anomaly_type: Optional[str] = None):
    """Get recent anomalies."""
    anomalies = storage.get_recent_anomalies(limit=limit, anomaly_type=anomaly_type)
    return {"status": "success", "anomalies": anomalies}


@app.get("/api/statistics")
async def get_statistics():
    """Get network statistics."""
    stats = storage.get_statistics()
    return {"status": "success", "statistics": stats}


@app.get("/api/device/{instance_number}")
async def get_device(instance_number: int):
    """Get specific device information."""
    device = storage.get_device_info(instance_number)
    
    if device:
        return {"status": "success", "device": device}
    else:
        raise HTTPException(status_code=404, detail="Device not found")


@app.post("/api/query")
async def process_query(request: QueryRequest):
    """Process a user query through the agent with streaming tool-call feedback."""
    if not agent_service:
        raise HTTPException(
            status_code=503, 
            detail="AI Agent service is not available. Please ensure the MCP server is running and the agent is properly configured."
        )

    async def event_generator():
        try:
            async with agent_lock:
                async for event in agent_service.process_query_stream(
                    request.query, session_id="chat_session"
                ):
                    yield event
        except Exception as e:
            print(f"[!] Error processing query: {e}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/")
async def get_index():
    """Serve the main HTML page."""
    html_file = Path("web/static/index.html")
    if html_file.exists():
        return FileResponse(html_file)
    else:
        return HTMLResponse(content="<h1>BACnet Security Monitor</h1><p>Frontend not found. Please create web/static/index.html</p>")


# Mount static files
static_dir = Path("web/static")
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
