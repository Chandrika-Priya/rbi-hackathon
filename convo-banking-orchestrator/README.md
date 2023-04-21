# Conversational Commerce Orchestrator

This application provides a REST interface which orchestrates calls to Vakyansh, AI4Bharat & Rasa models.

## How to build
```
$ ./gradlew clean build
```

## How to run
```
$ ./gradlew bootRun
```

Before running the application make sure all of Vakyansh (convo-commerce-v2t), AI4Bharat (convo-commerce-t2t) and Rasa (convo-commerce-business-context) REST services are up.
Also make sure these URLs are updated in the application.properties file.