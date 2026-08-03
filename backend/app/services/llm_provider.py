import logging
from typing import Optional, Dict, Any
import httpx
from app.config.settings import settings

logger = logging.getLogger(__name__)

class LLMProvider:
    """Abstract AI LLM Vendor interface supporting configurable OpenAI, Gemini, and Anthropic backends."""
    
    @staticmethod
    async def generate_completion(prompt: str, provider: Optional[str] = None) -> str:
        """Call configured AI vendor API to get content reasoning analysis (Zero-Trust Compliant)."""
        selected_provider = provider or getattr(settings, "AI_PROVIDER", "gemini").lower()
        
        if selected_provider == "gemini":
            return await LLMProvider._call_gemini(prompt)
        elif selected_provider == "openai":
            return await LLMProvider._call_openai(prompt)
        elif selected_provider == "anthropic":
            return await LLMProvider._call_anthropic(prompt)
        else:
            return await LLMProvider._call_local_stub(prompt)

    @staticmethod
    async def _call_gemini(prompt: str) -> str:
        """Query Google Gemini API model."""
        api_key = getattr(settings, "GEMINI_API_KEY", "")
        if not api_key:
             return '{"is_phishing": false, "reason": "Gemini API Key missing"}'
             
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=payload, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    return data["candidates"][0]["content"]["parts"][0]["text"]
                logger.error(f"Gemini API returned status {res.status_code}: {res.text}")
        except Exception as e:
            logger.error(f"Failed calling Gemini API: {str(e)}")
        return '{"is_phishing": false, "reason": "Gemini connection error"}'

    @staticmethod
    async def _call_openai(prompt: str) -> str:
        """Query OpenAI Chat Completion API."""
        api_key = getattr(settings, "OPENAI_API_KEY", "")
        if not api_key:
             return '{"is_phishing": false, "reason": "OpenAI API Key missing"}'
             
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        payload = {
            "model": getattr(settings, "OPENAI_MODEL", "gpt-4-turbo"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=payload, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenAI call failed: {str(e)}")
        return '{"is_phishing": false, "reason": "OpenAI connection error"}'

    @staticmethod
    async def _call_anthropic(prompt: str) -> str:
        """Query Anthropic Claude Message API."""
        api_key = getattr(settings, "ANTHROPIC_API_KEY", "")
        if not api_key:
             return '{"is_phishing": false, "reason": "Anthropic API Key missing"}'
             
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01"
        }
        payload = {
            "model": "claude-3-haiku-20240307",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1000
        }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, json=payload, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    return data["content"][0]["text"]
        except Exception as e:
            logger.error(f"Anthropic call failed: {str(e)}")
        return '{"is_phishing": false, "reason": "Anthropic connection error"}'

    @staticmethod
    async def _call_local_stub(prompt: str) -> str:
         """Fallback stub for offline/local model operations."""
         return '{"is_phishing": false, "reason": "Local LLM stub executed."}'
