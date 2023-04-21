package com.thoughtworks.ondc.poc.pocwrapper.context;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.ondc.poc.pocwrapper.asr.SpeechService;
import com.thoughtworks.ondc.poc.pocwrapper.translation.TranslationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping(path = "/v1/context")
@Slf4j
public class ContextController {
    private final ContextService contextService;
    private final TranslationService translationService;
    private final SpeechService speechService;

    public ContextController(ContextService contextService, TranslationService translationService, SpeechService speechService) {
        this.contextService = contextService;
        this.translationService = translationService;
        this.speechService = speechService;
    }

    @PostMapping(path = "/audio")
    IndicResponse getContextFromAudio(
            @RequestParam(name = "senderId") String senderId,
            @RequestParam(name = "sourceLang") String sourceLang,
            @RequestParam(name = "file") MultipartFile file,
            @RequestParam String metaData) throws IOException, InterruptedException {

        byte[] decodedBytes = Base64.getDecoder().decode(metaData);
        String decodedString = new String(decodedBytes);
        RequestData requestData = new ObjectMapper().readValue(decodedString, RequestData.class);

        log.info("Audio size is : " + file.getSize());
        String indicText = speechService.getTextFromFile(file, sourceLang);
        log.info("Audio to Text : " + indicText);

        log.info("Translating text... ");
        String translatedText = translationService.translateFromIndicToEnglish(indicText, sourceLang);
        log.info("Translated text : " + translatedText);

        log.info("Fetching context... ");
        ContextResponse response = contextService.getContext(translatedText,requestData);
        String message = response.getNextStep().getMessage();
        if(response.getData().size() == 0){
            return  new IndicResponse(indicText,translationService.translateFromEnglishToIndic(message, sourceLang));
        }
        String res = "";
        log.info("Translating to indic... ");
        for (Map<String, String> myMap : response.getData()) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : myMap.entrySet()) {
                sb.append(entry.getKey() + ":" + entry.getValue() + ",");
            }
            res += translationService.translateFromEnglishToIndic(sb.toString(), sourceLang);
        }
        IndicResponse indicResponse = new IndicResponse(indicText,res);
        log.info("Done");

        return indicResponse;

    }

    private ContextResponse failedContentResponse() {
        return ContextResponse.builder()
                .nextStep(
                        new ContextResponse
                                .NextStep(
                                        "I didn't catch that, please try again",
                                new ArrayList<>()
                        )
                ).build();
    }
}
