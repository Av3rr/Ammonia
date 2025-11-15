#!/usr/bin/env python3
# recon_tool_ffuf_sgr.py
# FFUF wrapper for the SGR agent modeled after your detailed ReconnaissanceToolNmap example.

from __future__ import annotations
import asyncio
import json
import logging
import os
import shutil
from typing import TYPE_CHECKING, Dict, Any, List, Optional

from pydantic import Field
from sgr_deep_research.core.base_tool import BaseTool

if TYPE_CHECKING:
    from sgr_deep_research.core.models import ResearchContext

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class ReconnaissanceToolFfuf(BaseTool):
    """
    FFUF wrapper for the SGR agent.

    This tool is intended to be called by the LLM-driven agent to perform web
    content/endpoint discovery using ffuf. It runs ffuf as a subprocess (JSON output
    to a temporary file), parses the JSON and returns a JSON-encoded string
    containing the parsed results or an error description.

    Notes for the LLM:
    - Use this tool when you need to discover hidden directories/files, find
      interesting endpoints, or enumerate common paths on a web host.
    - Prefer smaller wordlists for quick reconnaissance; use larger lists when
      thoroughness is required (but expect longer runtime and more noise).
    - Respect authorization and scope in ResearchContext before calling.
    """

    # LLM-facing arguments (descriptions are read by LLM and influence behavior)
    reasoning: str = Field(
        description=(
            "FFUF (Fuzz Faster U Fool) — инструмент для брута/фаззинга URL-путей и параметров. "
            "Здесь вы описываете коротко, зачем запускаете этот поиск (метаданные для агента)."
        )
    )
    target: str = Field(
        description=(
            "Цель сканирования. Можно указать IP или host:port (напр. '192.168.1.107' или 'example.com:8080'), "
            "либо полный URL/шаблон содержащий 'FUZZ' (напр. 'http://example.com/FUZZ' или 'https://foo.bar/FUZZ'). "
            "Если передаёте только хост — обёртка добавит 'http://' и '/FUZZ'."
        )
    )
    wordlist: str = Field(
        description="Путь к словарю на диске, который ffuf будет использовать (напр. /usr/share/wordlists/dirb/common.txt)."
    )
    threads: int = Field(default=40, description="Количество потоков (-t) для ffuf.")
    extensions: Optional[str] = Field(
        default=None,
        description="Опционально: comma-separated list для -e (напр. 'php,html,txt'). Если None — опция не добавляется."
    )
    status_codes: Optional[str] = Field(
        default=None,
        description="Опционально: comma-separated список статус-кодов для -mc (напр. '200,301,302')."
    )
    output_file: str = Field(
        default="ffuf-results.json",
        description="Временный JSON-файл, который ffuf запишет; файл будет удалён после чтения."
    )
    timeout_seconds: int = Field(
        default=600,
        description="Максимальное время ожидания выполнения ffuf в секундах (таймаут)."
    )
    extra_args: Optional[List[str]] = Field(
        default=None,
        description="Опционально: список дополнительных аргументов к ffuf (например, ['-H', 'Cookie: ...'])."
    )

    async def __call__(self, context: ResearchContext) -> str:
        """
        Запускает ffuf (async), парсит JSON-вывод и возвращает JSON-строку.

        Возвращаемая структура (JSON):
        {
          "target": "<target>",
          "cmd": ["ffuf", ...],
          "results": [
              {
                "input": "...",
                "url": "...",
                "status": 200,
                "length": 1234,
                "words": 10,
                "redirectlocation": "...",
                "line": "...",
                "tags": [...],
                "title": "..."
              }, ...
          ],
          "metadata": { "elapsed": 1.23, ... }  # whatever ffuf provides
        }

        В случае ошибки возвращается JSON с полем "error".
        """
        logger.info(f"Запуск ReconnaissanceToolFfuf для цели: {self.target}")
        print(f"[ReconnaissanceToolFfuf] Starting ffuf target={self.target} wordlist={self.wordlist}")

        # Ensure ffuf exists
        if shutil.which("ffuf") is None:
            msg = "ffuf not found in PATH. Установите ffuf и убедитесь, что он доступен."
            logger.exception(msg)
            print(f"[ReconnaissanceToolFfuf] EXCEPTION: {msg}")
            return json.dumps({"error": msg}, ensure_ascii=False)

        # Ensure wordlist exists
        if not os.path.isfile(self.wordlist):
            msg = f"wordlist not found: {self.wordlist}"
            logger.error(msg)
            print(f"[ReconnaissanceToolFfuf] ERROR: {msg}")
            return json.dumps({"error": msg}, ensure_ascii=False)

        # Build URL template
        if self.target.startswith("http://") or self.target.startswith("https://"):
            url_template = self.target
            if "FUZZ" not in url_template:
                url_template = url_template.rstrip("/") + "/FUZZ"
        else:
            url_template = f"http://{self.target}/FUZZ"

        # Build ffuf command
        cmd = [
            "ffuf",
            "-w", self.wordlist,
            "-u", url_template,
            "-t", str(self.threads),
            "-of", "json",
            "-o", self.output_file,
        ]

        if self.extensions:
            cmd += ["-e", self.extensions]
        if self.status_codes:
            cmd += ["-mc", self.status_codes]
        if self.extra_args:
            cmd += list(self.extra_args)

        logger.debug(f"Constructed ffuf command: {' '.join(cmd)}")
        print(f"[ReconnaissanceToolFfuf] Command: {' '.join(cmd)}")

        # Run ffuf
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                msg = f"ffuf timed out after {self.timeout_seconds} seconds"
                logger.error(msg)
                print(f"[ReconnaissanceToolFfuf] ERROR: {msg}")
                return json.dumps({"error": msg}, ensure_ascii=False)

            rc = proc.returncode
            stderr_text = (stderr.decode("utf-8", errors="ignore") or "").strip()
            logger.debug(f"ffuf finished rc={rc}; stderr_len={len(stderr_text)}")
            if rc != 0:
                logger.warning("ffuf exited with non-zero rc=%s; attempting to read partial output if present", rc)
                print(f"[ReconnaissanceToolFfuf] ffuf rc={rc}; stderr: {stderr_text}")

                if os.path.exists(self.output_file):
                    try:
                        with open(self.output_file, "r", encoding="utf-8", errors="replace") as f:
                            raw = f.read()
                        parsed_raw = json.loads(raw) if raw.strip() else None
                        try:
                            os.remove(self.output_file)
                        except Exception:
                            pass
                        if parsed_raw is not None:
                            structured = self._parse_ffuf_json(parsed_raw)
                            return json.dumps(structured, ensure_ascii=False, indent=2)
                    except Exception as e:
                        logger.exception("Failed to read/parse ffuf output after non-zero rc: %s", e)

                return json.dumps({"error": "ffuf failed", "rc": rc, "stderr": stderr_text}, ensure_ascii=False)

            # rc == 0: read output file
            if not os.path.exists(self.output_file):
                msg = f"ffuf did not produce output file (stderr: {stderr_text})"
                logger.error(msg)
                print(f"[ReconnaissanceToolFfuf] ERROR: {msg}")
                return json.dumps({"error": msg}, ensure_ascii=False)

            try:
                with open(self.output_file, "r", encoding="utf-8", errors="replace") as f:
                    raw = f.read()
                parsed_raw = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError as e:
                logger.exception("Failed to decode ffuf JSON output: %s", e)
                return json.dumps({"error": "failed to parse ffuf JSON output", "msg": str(e)}, ensure_ascii=False)
            except Exception as e:
                logger.exception("Unexpected error reading ffuf output: %s", e)
                return json.dumps({"error": f"unexpected error reading ffuf output: {str(e)}"}, ensure_ascii=False)
            finally:
                try:
                    os.remove(self.output_file)
                except Exception:
                    pass

            # Transform to a conservative structured representation
            structured = self._parse_ffuf_json(parsed_raw)
            logger.info("ffuf parse finished, returning JSON")
            print("[ReconnaissanceToolFfuf] Parse complete, returning JSON result")
            return json.dumps(structured, ensure_ascii=False, indent=2)

        except FileNotFoundError:
            msg = "ffuf executable not found. Установите ffuf и убедитесь, что он доступен в PATH."
            logger.exception(msg)
            print(f"[ReconnaissanceToolFfuf] EXCEPTION: {msg}")
            return json.dumps({"error": msg}, ensure_ascii=False)
        except Exception as e:
            logger.exception("Unexpected error while running ffuf")
            print(f"[ReconnaissanceToolFfuf] EXCEPTION: {e}")
            return json.dumps({"error": f"unexpected error: {str(e)}"}, ensure_ascii=False)

    def _parse_ffuf_json(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """
        Conservative parser for ffuf JSON structure.

        ffuf JSON generally contains top-level metadata and "results": [ {...}, ... ].
        This parser extracts safe fields from each result and returns a structured dict.
        """
        out: Dict[str, Any] = {
            "target": self.target,
            "cmd": None,
            "results": [],
            "metadata": {}
        }

        # Attempt to include command-echo if ffuf provided it (some versions include "command" or "cmdline")
        if isinstance(parsed, dict):
            for key in ("command", "cmdline", "command_line"):
                if key in parsed:
                    out["cmd"] = parsed.get(key)
                    break

            # attach top-level metadata (elapsed, summary etc.) if present
            meta_keys = {"duration", "start", "time", "summary", "stats", "results_count", "elapsed"}
            for k in parsed.keys():
                if k in meta_keys or k == "results":
                    continue
                # include other top-level keys into metadata to preserve info
                out["metadata"][k] = parsed.get(k)

            results = parsed.get("results") or parsed.get("grep") or parsed.get("matches") or []
            if not isinstance(results, list):
                results = []

            for r in results:
                # conservative extraction: use get(...) for fields that may or may not exist
                item = {
                    "input": r.get("input") or r.get("word") or r.get("payload") or None,
                    "url": r.get("url") or r.get("uri") or None,
                    "status": r.get("status") or None,
                    "length": r.get("length") or r.get("size") or None,
                    "words": r.get("words") or None,
                    "redirectlocation": r.get("redirectlocation") or r.get("redirect") or None,
                    "title": r.get("title") or None,
                    "lines": r.get("lines") or r.get("line") or None,
                    "tags": r.get("tags") or None,
                    # Keep the raw result so nothing important is lost:
                    "raw": r
                }
                out["results"].append(item)

        return out
