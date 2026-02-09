import json
import os
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

class ThreatClassifier:
    def __init__(self, api_key, provider="openai"):
        self.provider = provider
        self.api_key = api_key
        self.llm = self._initialize_llm()

    def _initialize_llm(self):
        if self.provider == "openai":
            return ChatOpenAI(temperature=0, openai_api_key=self.api_key, model="gpt-4o")
        elif self.provider == "gemini":
            return ChatGoogleGenerativeAI(temperature=0, google_api_key=self.api_key, model="gemini-1.5-pro")
        else:
            raise ValueError("Invalid provider. Choose 'openai' or 'gemini'.")

    def classify_threat(self, log_entry):
        """
        Classifies a single log entry using the LLM.
        """
        prompt = f"""
        You are a Cyber Security Analyst AI. Analyze the following network log entry marked as anomalous:
        {log_entry}

        Classify the potential threat into one of these categories:
        - DDoS
        - Brute Force
        - Port Scan
        - Malware
        - Unknown (if not clear)

        Provide a structured JSON response with:
        - attack_type
        - severity (Low, Medium, High, Critical)
        - description (brief explanation)
        - mitigation (step-by-step action)

        Output ONLY valid JSON.
        """

        try:
            response = self.llm.invoke([
                SystemMessage(content="You are a strict JSON output generator for cyber security analysis."),
                HumanMessage(content=prompt)
            ])
            
            # Clean up potential markdown formatting in response
            content = response.content.replace("```json", "").replace("```", "").strip()
            return json.loads(content)
        except Exception as e:
            print(f"Error classifying threat: {e}")
            return {
                "attack_type": "Error",
                "severity": "Unknown",
                "description": "Failed to classify due to LLM error.",
                "mitigation": "Check system logs."
            }
