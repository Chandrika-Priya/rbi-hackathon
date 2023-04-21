package com.thoughtworks.ondc.poc.pocwrapper.asr;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class SpeechService {
    private final SpeechWebClient speechWebClient;

    @Autowired
    public SpeechService(SpeechWebClient speechWebClient) {
        this.speechWebClient = speechWebClient;
    }

    public String getTextFromFile(MultipartFile file, String sourceLang) {
        return speechWebClient.getText(file,sourceLang).getTranscript();
    }

}
