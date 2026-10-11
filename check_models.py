import os
import sys
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    if len(sys.argv) > 1:
        api_key = sys.argv[1]
    else:
        api_key = input("Enter your Gemini API key: ").strip()

if not api_key:
    print("Error: No API key provided.")
    sys.exit(1)

try:
    client = genai.Client(api_key=api_key)
    supported_models = [
        m.name for m in client.models.list()
        if m.supported_actions and "generateContent" in m.supported_actions
    ]
    print(f"\nFound {len(supported_models)} model(s) supporting 'generateContent':")
    for name in supported_models:
        print(f" - {name}")

    # Cleaned short names
    short_names = [m.replace("models/", "") for m in supported_models]
    text_models = [
        m for m in short_names 
        if "gemini" in m.lower() and not any(x in m.lower() for x in ["embedding", "imagen", "veo", "aqa"])
    ]
    if text_models:
        print(f"\nRecommended first text model for app.py: '{text_models[0]}'")
    elif short_names:
        print(f"\nRecommended first model for app.py: '{short_names[0]}'")
except Exception as e:
    print(f"\nFailed to query models: {e}")
