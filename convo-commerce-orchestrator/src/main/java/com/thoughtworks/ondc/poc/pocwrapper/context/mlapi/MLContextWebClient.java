package com.thoughtworks.ondc.poc.pocwrapper.context.mlapi;

import com.thoughtworks.ondc.poc.pocwrapper.context.RequestData;
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
import java.util.Map;

@Service
public class MLContextWebClient implements InitializingBean {

    @Value("${api.context.url}")
    private String baseUrl;

    private WebClient webClient;

    @Autowired
    private WebClient.Builder builder;

    public MLContextResponse getContext(String text, RequestData requestData) {
        Map<String, Object> request = new HashMap<>();
        request.put("message", text);
        request.put("sender_id", "convo-commerce-ui");
        request.put("metadata", requestData);

        return webClient.post()
                .uri("/next-step")
                .body(BodyInserters.fromValue(request))
                .retrieve()
                .bodyToMono(MLContextResponse.class)
                .block();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        HttpClient httpClient = HttpClient.create().baseUrl(baseUrl).resolver(DefaultAddressResolverGroup.INSTANCE);
        this.webClient = builder.clientConnector(new ReactorClientHttpConnector(httpClient)).build();
    }
}
