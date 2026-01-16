#!/usr/bin/env python3
"""
Quick test to verify Gemini adapter works
"""

import os
from pathlib import Path

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
        print(f"Loaded environment from {env_path}")
except ImportError:
    print("Note: Install python-dotenv to auto-load .env files")
    print("      Or set environment variable manually")

from sigil_llm_adapter import GeminiAdapter

print("Testing Gemini Adapter...")
print()

# Check for API key
api_key = os.getenv('GOOGLE_API_KEY')
if not api_key:
    print("No GOOGLE_API_KEY found in environment.")
    print()
    print("To get an API key:")
    print("  1. Go to https://aistudio.google.com/app/apikey")
    print("  2. Click 'Create API key'")
    print("  3. Set it: $env:GOOGLE_API_KEY = 'your-key-here'")
    print()
    exit(1)

print(f"API Key found: {api_key[:10]}...{api_key[-4:]}")
print()

# Test with gemini-2.0-flash-exp
print("Testing gemini-2.0-flash-exp...")
try:
    adapter = GeminiAdapter(model='gemini-2.0-flash-exp')
    response = adapter.complete("What is 2+2? Answer with just the number.")
    print(f"Response: {response}")
    print("[PASS] Gemini 2.0 Flash works!")
except Exception as e:
    print(f"[FAIL] Error: {e}")

print()

# Test with gemini-1.5-flash (stable version)
print("Testing gemini-1.5-flash...")
try:
    adapter = GeminiAdapter(model='gemini-1.5-flash')
    response = adapter.complete("What is the capital of France? Answer with just the city name.")
    print(f"Response: {response}")
    print("[PASS] Gemini 1.5 Flash works!")
except Exception as e:
    print(f"[FAIL] Error: {e}")

print()
print("Gemini adapter is ready! You can now use it in:")
print("  - example_usage.py")
print("  - test_real_injection.py")
print()
