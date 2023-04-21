package com.thoughtworks.ondc.poc.pocwrapper.translation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.thoughtworks.ondc.poc.pocwrapper.cache.CacheHelper;
import net.sf.ehcache.Element;
import net.sf.ehcache.Cache;
import java.util.Collections;
import java.util.ArrayList;

import java.util.List;

@Service
public class TranslationService {
    private TranslationWebClient translationWebClient;

    @Autowired
    CacheHelper cacheHelper;

    @Autowired
    public TranslationService(TranslationWebClient translationWebClient) {
        this.translationWebClient = translationWebClient;
    }

    public String translateFromHindiToEnglish(String text) {
        return translateFromIndicToEnglish(text, "hi");
    }

    public String translateFromIndicToEnglish(String text, String source) {
        Cache cache = cacheHelper.getAI4BharatCacheFile();
        String response;
        response = translationWebClient.translate(text, source, "en").getTranslatedText();
        return response;
    }

    public String translateFromEnglishToIndic(String text, String target) {
        Cache cache = cacheHelper.getAI4BharatCacheFile();
        String response;
        List<String> translatedText = translationWebClient.translateEnglishToIndic(new ArrayList<>(Collections.singleton(text)), target).getTranslatedText();
        response = translatedText.get(0);
        return response;
    }
}
