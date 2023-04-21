package com.thoughtworks.ondc.poc.pocwrapper.translation;

import io.netty.resolver.DefaultAddressResolverGroup;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class TranslationWebClient implements InitializingBean {

    @Value("${api.translation.url}")
    private String baseUrl;

    private WebClient webClient;

    @Autowired
    private WebClient.Builder webClientBuilder;

    public TranslationResponse translate(String text){
        return translate(text, "hi", "en");
    }

    public TranslationResponse translate(String text, String source, String target){
        return this.webClient.post()
                .uri("/translate")
                .body(BodyInserters.fromFormData("q", text)
                        .with("source", source)
                        .with("target",target)
                        .with("format","text"))
                .retrieve()
                .bodyToMono(TranslationResponse.class)
                .block();

    }

    public BulkTranslationResponse translateEnglishToIndic(List<String> texts, String target){
        Map<String, Object> map = new HashMap<>();
        map.put("q", texts);
        map.put("source", "en");
        map.put("target", target);
        return this.webClient.post()
                .uri("/translate/e2i")
                .body(BodyInserters.fromValue(map))
                .retrieve()
                .bodyToMono(BulkTranslationResponse.class)
                .block();

    }

    @Override
    public void afterPropertiesSet() throws Exception {
        HttpClient httpClient = HttpClient.create().baseUrl(baseUrl).resolver(DefaultAddressResolverGroup.INSTANCE);
        this.webClient = webClientBuilder.clientConnector(new ReactorClientHttpConnector(httpClient)).build();
    }
}
