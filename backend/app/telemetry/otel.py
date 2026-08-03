import time
import functools
import logging
import uuid
import contextvars
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("guardianmail.telemetry")

# Context variable to hold active Trace ID across asynchronous tasks
active_trace_id = contextvars.ContextVar("active_trace_id", default="")
active_span_id = contextvars.ContextVar("active_span_id", default="")

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
    
    # Initialize standard OpenTelemetry Provider
    provider = TracerProvider()
    processor = SimpleSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    
    otel_tracer = trace.get_tracer("guardianmail")
    HAS_OTEL = True
except ImportError:
    otel_tracer = None
    HAS_OTEL = False

def get_current_trace_id() -> str:
    """Retrieve trace identifier from context variables or return empty."""
    val = active_trace_id.get()
    if not val:
        # Auto-generate a Trace ID if none exists in current asynchronous pipeline
        val = str(uuid.uuid4())
        active_trace_id.set(val)
    return val

def trace_span(name: str):
    """Decorator to trace execution duration and capture telemetry metrics for standard spans."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if HAS_OTEL and otel_tracer:
            @functools.wraps(func)
            async def async_otel_wrapper(*args, **kwargs):
                with otel_tracer.start_as_current_span(name) as span:
                    # Propagate context trace attributes
                    trace_id = span.get_span_context().trace_id
                    active_trace_id.set(format(trace_id, "032x") if isinstance(trace_id, int) else str(trace_id))
                    return await func(*args, **kwargs)

            @functools.wraps(func)
            def sync_otel_wrapper(*args, **kwargs):
                with otel_tracer.start_as_current_span(name) as span:
                    trace_id = span.get_span_context().trace_id
                    active_trace_id.set(format(trace_id, "032x") if isinstance(trace_id, int) else str(trace_id))
                    return func(*args, **kwargs)

            return async_otel_wrapper if asyncio.iscoroutinefunction(func) else sync_otel_wrapper
        else:
            # Fallback to high-performance local SRE structured JSON logging tracing
            @functools.wraps(func)
            async def async_fallback_wrapper(*args, **kwargs):
                t_id = get_current_trace_id()
                s_id = str(uuid.uuid4())[:16]
                
                token_trace = active_trace_id.set(t_id)
                token_span = active_span_id.set(s_id)
                
                start_time = time.perf_counter()
                try:
                    res = await func(*args, **kwargs)
                    elapsed = (time.perf_counter() - start_time) * 1000.0  # ms
                    logger.info(
                        f"Span '{name}' completed successfully in {elapsed:.2f}ms",
                        extra={
                            "trace_id": t_id,
                            "span_id": s_id,
                            "span_name": name,
                            "duration_ms": elapsed,
                            "status": "success"
                        }
                    )
                    return res
                except Exception as e:
                    elapsed = (time.perf_counter() - start_time) * 1000.0  # ms
                    logger.error(
                        f"Span '{name}' failed after {elapsed:.2f}ms with error: {str(e)}",
                        extra={
                            "trace_id": t_id,
                            "span_id": s_id,
                            "span_name": name,
                            "duration_ms": elapsed,
                            "status": "failed",
                            "error": str(e)
                        }
                    )
                    raise
                finally:
                    active_trace_id.reset(token_trace)
                    active_span_id.reset(token_span)

            @functools.wraps(func)
            def sync_fallback_wrapper(*args, **kwargs):
                t_id = get_current_trace_id()
                s_id = str(uuid.uuid4())[:16]
                
                token_trace = active_trace_id.set(t_id)
                token_span = active_span_id.set(s_id)
                
                start_time = time.perf_counter()
                try:
                    res = func(*args, **kwargs)
                    elapsed = (time.perf_counter() - start_time) * 1000.0  # ms
                    logger.info(
                        f"Span '{name}' completed successfully in {elapsed:.2f}ms",
                        extra={
                            "trace_id": t_id,
                            "span_id": s_id,
                            "span_name": name,
                            "duration_ms": elapsed,
                            "status": "success"
                        }
                    )
                    return res
                except Exception as e:
                    elapsed = (time.perf_counter() - start_time) * 1000.0  # ms
                    logger.error(
                        f"Span '{name}' failed after {elapsed:.2f}ms with error: {str(e)}",
                        extra={
                            "trace_id": t_id,
                            "span_id": s_id,
                            "span_name": name,
                            "duration_ms": elapsed,
                            "status": "failed",
                            "error": str(e)
                        }
                    )
                    raise
                finally:
                    active_trace_id.reset(token_trace)
                    active_span_id.reset(token_span)

            import asyncio
            return async_fallback_wrapper if asyncio.iscoroutinefunction(func) else sync_fallback_wrapper
    return decorator
