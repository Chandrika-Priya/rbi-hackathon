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
        if(cache.get(text)==null) {
            response = translationWebClient.translate(text, source, "en").getTranslatedText();
            cache.put(new Element(text, response));
        }
        else
        {
            Object object = cache.get(text).getObjectValue();
            response = (String) object;
        }
        return response;
    }

//    public List<String> translateFromEnglishToIndic(List<String> text, String target) {
//        return translationWebClient.translateEnglishToIndic(text, target).getTranslatedText();
//    }

    public String translateFromEnglishToIndic(String text, String target) {
        Cache cache = cacheHelper.getAI4BharatCacheFile();
        String response;
        if (cache.get(text) == null) {
            List<String> translatedText = translationWebClient.translateEnglishToIndic(new ArrayList<>(Collections.singleton(text)), target).getTranslatedText();
            cache.put(new Element(text, translatedText.get(0)));
            response = translatedText.get(0);
        } else {
            Object object = cache.get(text).getObjectValue();
            response = (String) object;
        }
        return response;
    }
}
