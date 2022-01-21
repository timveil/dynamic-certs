FROM maven:3.8-eclipse-temurin-17 as builder
WORKDIR /app
COPY ./pom.xml ./pom.xml
RUN mvn dependency:go-offline -B
COPY ./src ./src
RUN mvn package && cp target/*.jar application.jar
RUN java -Djarmode=layertools -jar application.jar extract

FROM cockroachdb/cockroach:latest as cockroach

FROM eclipse-temurin:17-jdk
COPY --from=builder /app/dependencies/ ./
COPY --from=builder /app/snapshot-dependencies/ ./
COPY --from=builder /app/spring-boot-loader/ ./
COPY --from=builder /app/application/ ./
COPY --from=cockroach /cockroach/ ./
COPY ./config ./config

RUN touch ./config/index.txt
RUN touch ./config/serial
RUN echo '01' > /config/serial

RUN mkdir -pv ./.cockroach-internal
RUN mkdir -pv ./.cockroach-certs

EXPOSE 9999

ENTRYPOINT ["java", "org.springframework.boot.loader.JarLauncher"]