# Use the official lightweight Python image.
# https://hub.docker.com/_/python
FROM python:3.8.9
# FROM python:3.8.12-slim-bullseye

# Allow statements and log messages to immediately appear in the Knative logs
# ENV PYTHONUNBUFFERED True

# Copy local code to the container image.
ENV APP_HOME /app
ENV T2T_MODEL_PATH ${APP_HOME}/indic2models
WORKDIR $APP_HOME
#COPY fairseq /app/fairseq
COPY indic2models /app/indic2models
COPY indicTrans /app/indicTrans
COPY inference ./inference
COPY model_configs ./model_configs
COPY *.py ./
COPY requirements.txt ./

RUN \
apt-get update && \
apt-get install unzip wget -y && \
rm -rf /var/lib/apt/lists/*

RUN apt-get install unzip

# #download the model
# RUN \
# wget https://storage.googleapis.com/ondc-hackathon/indic-en.zip -q;
# unzip indic-en.zip;
# rm -rf indic-en.zip;
# python convo_comm_api.py;

# wget https://storage.googleapis.com/ondc-hackathon/LICENSE.zip;
# unzip LICENSE.zip;
# rm -rf LICENSE.zip;
# python convo_comm_api.py;

# wget https://storage.googleapis.com/ondc-hackathon/indic-en.zip -q;
# unzip indic-en.zip;
# rm -rf indic-en.zip;
# python convo_comm_api.py


# Install production dependencies.
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install ./inference
# Run the web service on container startup. Here we use the gunicorn
# webserver, with one worker process and 8 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.
# CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 convo_comm_api:app
CMD ["python", "/app/api.py"]