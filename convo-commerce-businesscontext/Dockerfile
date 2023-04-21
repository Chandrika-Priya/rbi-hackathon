FROM python:3.8.9

WORKDIR /app
COPY .. /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install rasa
RUN pip install --upgrade aio_pika
RUN rasa train
RUN pip install Flask

RUN ["chmod", "+x", "/app/commands.sh"]

ENTRYPOINT ["/app/commands.sh"]