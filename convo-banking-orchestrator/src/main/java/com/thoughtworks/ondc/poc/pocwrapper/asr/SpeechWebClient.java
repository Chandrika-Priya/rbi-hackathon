package com.thoughtworks.ondc.poc.pocwrapper.asr;

import io.netty.resolver.DefaultAddressResolverGroup;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

@Service
public class SpeechWebClient implements InitializingBean {

    @Value("${api.speech.url}")
    private String baseUrl;

    private WebClient webClient;

    @Autowired
    private WebClient.Builder webClientBuilder;

    public SpeechResponse getText(MultipartFile audioFile, String sourceLang) {

        MultipartBodyBuilder bodyBuilder = new MultipartBodyBuilder();
        bodyBuilder.part("file", audioFile.getResource());
        bodyBuilder.part("language", sourceLang);
        MultiValueMap<String, HttpEntity<?>> body = bodyBuilder.build();

        return this.webClient.post()
                .uri("/v2/decode")
                .body(BodyInserters.fromMultipartData(body))
                .retrieve()
                .bodyToMono(SpeechResponse.class)
                .block();
    }

    @Override
    public void afterPropertiesSet() {
        HttpClient httpClient = HttpClient.create().baseUrl(baseUrl).resolver(DefaultAddressResolverGroup.INSTANCE);
        this.webClient = webClientBuilder.clientConnector(new ReactorClientHttpConnector(httpClient)).build();
    }
}
