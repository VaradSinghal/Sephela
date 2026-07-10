"""Streaming handler for real-time LLM output processing."""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from ai.llm.client import StreamingChunk, LLMResponse


@dataclass
class StreamingState:
    """State of a streaming response."""
    chunks: List[StreamingChunk] = field(default_factory=list)
    full_content: str = ""
    total_tokens: int = 0
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    is_complete: bool = False
    error: Optional[str] = None


class StreamingHandler:
    """Handles streaming LLM responses with buffering and parsing."""

    def __init__(
        self,
        on_chunk: Optional[Callable[[StreamingChunk], None]] = None,
        on_complete: Optional[Callable[[LLMResponse], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        buffer_size: int = 1024,
    ):
        self.on_chunk = on_chunk
        self.on_complete = on_complete
        self.on_error = on_error
        self.buffer_size = buffer_size
        self.state = StreamingState()

    async def process_stream(
        self,
        stream: AsyncIterator[StreamingChunk],
    ) -> LLMResponse:
        """Process a streaming response into a complete response."""
        self.state = StreamingState()

        try:
            async for chunk in stream:
                self.state.chunks.append(chunk)
                self.state.full_content += chunk.content
                self.state.total_tokens = chunk.tokens_so_far

                if self.on_chunk:
                    try:
                        self.on_chunk(chunk)
                    except Exception as e:
                        # Don't let callback errors break the stream
                        pass

                if chunk.is_final:
                    break

            self.state.completed_at = datetime.utcnow()
            self.state.is_complete = True

            response = LLMResponse(
                content=self.state.full_content,
                model="",  # Will be filled by caller
                provider=None,  # Will be filled by caller
                tokens_used=self.state.total_tokens,
                latency_ms=int(
                    (self.state.completed_at - self.state.started_at).total_seconds() * 1000
                ),
                finish_reason="stop",
                raw_response={"chunks": len(self.state.chunks)},
            )

            if self.on_complete:
                try:
                    self.on_complete(response)
                except Exception:
                    pass

            return response

        except Exception as e:
            self.state.error = str(e)
            if self.on_error:
                try:
                    self.on_error(e)
                except Exception:
                    pass
            raise

    def get_partial_content(self) -> str:
        """Get current partial content."""
        return self.state.full_content

    def get_state(self) -> StreamingState:
        """Get current streaming state."""
        return self.state


class JSONStreamingParser:
    """Parses streaming JSON output, handling partial chunks."""

    def __init__(self, target_schema: Optional[type] = None):
        self.target_schema = target_schema
        self.buffer = ""
        self.depth = 0
        self.in_string = False
        self.escape_next = False

    def feed(self, chunk: str) -> List[Dict[str, Any]]:
        """Feed a chunk and return any complete JSON objects."""
        self.buffer += chunk
        results = []

        i = 0
        while i < len(self.buffer):
            char = self.buffer[i]

            if self.escape_next:
                self.escape_next = False
            elif char == "\\" and self.in_string:
                self.escape_next = True
            elif char == '"' and not self.escape_next:
                self.in_string = not self.in_string
            elif not self.in_string:
                if char in "{[":
                    self.depth += 1
                elif char in "}]":
                    self.depth -= 1
                    if self.depth == 0:
                        # Potential complete object
                        obj_str = self.buffer[:i+1]
                        try:
                            obj = json.loads(obj_str)
                            results.append(obj)
                            self.buffer = self.buffer[i+1:]
                            i = -1  # Will be incremented to 0
                        except json.JSONDecodeError:
                            pass

            i += 1

        return results

    def get_partial(self) -> Optional[Dict[str, Any]]:
        """Try to parse current buffer as partial JSON."""
        try:
            return json.loads(self.buffer)
        except json.JSONDecodeError:
            return None


class StructuredStreamingHandler(StreamingHandler):
    """Streaming handler that parses structured JSON output."""

    def __init__(
        self,
        schema_class: type,
        on_chunk: Optional[Callable[[StreamingChunk], None]] = None,
        on_complete: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        buffer_size: int = 1024,
    ):
        super().__init__(on_chunk, on_error=on_error, buffer_size=buffer_size)
        self.schema_class = schema_class
        self.json_parser = JSONStreamingParser(schema_class)
        self._on_complete = on_complete

    async def process_stream(
        self,
        stream: AsyncIterator[StreamingChunk],
    ) -> Any:
        """Process stream and parse as structured output."""
        self.state = StreamingState()

        try:
            parsed_objects = []

            async for chunk in stream:
                self.state.chunks.append(chunk)
                self.state.full_content += chunk.content
                self.state.total_tokens = chunk.tokens_so_far

                if self.on_chunk:
                    try:
                        self.on_chunk(chunk)
                    except Exception:
                        pass

                # Try to parse JSON objects from chunk
                objects = self.json_parser.feed(chunk.content)
                parsed_objects.extend(objects)

                if chunk.is_final:
                    break

            self.state.completed_at = datetime.utcnow()
            self.state.is_complete = True

            # Validate against schema if we have parsed objects
            if parsed_objects:
                # Use the last complete object (or merge if array)
                final_obj = parsed_objects[-1] if len(parsed_objects) == 1 else parsed_objects
                try:
                    validated = self.schema_class(**final_obj)
                except Exception as e:
                    # Try to salvage with partial parse
                    partial = self.json_parser.get_partial()
                    if partial:
                        validated = self.schema_class(**partial)
                    else:
                        raise e
            else:
                # No complete objects parsed, try partial
                partial = self.json_parser.get_partial()
                if partial:
                    validated = self.schema_class(**partial)
                else:
                    raise ValueError("No valid JSON parsed from stream")

            response = LLMResponse(
                content=self.state.full_content,
                model="",
                provider=None,
                tokens_used=self.state.total_tokens,
                latency_ms=int(
                    (self.state.completed_at - self.state.started_at).total_seconds() * 1000
                ),
                finish_reason="stop",
                raw_response={"parsed": validated.model_dump() if hasattr(validated, 'model_dump') else str(validated)},
            )

            if self._on_complete:
                try:
                    self._on_complete(validated)
                except Exception:
                    pass

            return validated

        except Exception as e:
            self.state.error = str(e)
            if self.on_error:
                try:
                    self.on_error(e)
                except Exception:
                    pass
            raise