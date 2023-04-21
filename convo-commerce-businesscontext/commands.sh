#!/bin/bash
set -m
rasa run actions &
rasa run -m models --enable-api --cors "*" &
python api/main.py & fg
