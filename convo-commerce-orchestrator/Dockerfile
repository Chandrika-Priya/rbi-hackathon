FROM openjdk:11-jdk-slim
COPY build/libs/poc-wrapper-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app.jar"]