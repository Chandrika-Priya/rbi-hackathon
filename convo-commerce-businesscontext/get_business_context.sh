#!/bin/bash
set -m
rasa run actions &
docker run -p 8000:8000 rasa/duckling &
python api/main.py &
rasa run -m models --enable-api --cors “*” --debug
