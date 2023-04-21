package com.thoughtworks.ondc.poc.pocwrapper.asr;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/v1/speech")
public class SpeechController {
    private final SpeechService speechService;

    @Autowired
    public SpeechController(SpeechService speechService) {
        this.speechService = speechService;
    }

    @PostMapping("/text/file")
    ResponseEntity<SpeechResponse> getAudioToText(@RequestParam("file") MultipartFile file, @RequestParam String sourceLang) {
        String response = speechService.getTextFromFile(file,sourceLang);
        return ResponseEntity.ok(SpeechResponse.builder()
                .transcript(response)
                .build());
    }
}

