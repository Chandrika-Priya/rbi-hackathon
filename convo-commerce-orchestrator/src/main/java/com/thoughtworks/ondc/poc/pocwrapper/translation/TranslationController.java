package com.thoughtworks.ondc.poc.pocwrapper.translation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/v1/translate")
public class TranslationController {
    private final TranslationService translationService;

    @Autowired
    public TranslationController(TranslationService translationService) {
        this.translationService = translationService;
    }

    @GetMapping(path = "/hindi")
    ResponseEntity<String> getEnglishFromHindi(@RequestParam String text){
        String response = translationService.translateFromHindiToEnglish(text);
        return ResponseEntity.ok(response);
    }

    @GetMapping(path = "i2e")
    ResponseEntity<String> getEnglishFromIndic(@RequestParam String text, @RequestParam String source) {
        String response = translationService.translateFromIndicToEnglish(text, source);
        return ResponseEntity.ok(response);
    }

//    @GetMapping(path = "e2i")
//    ResponseEntity<String> getIndicFromEnglish(@RequestParam String text, @RequestParam String target){
//        List<String> response = translationService.translateFromEnglishToIndic(Collections.singletonList(text), target);
//        if (response == null || response.size() == 0) {
//            return ResponseEntity.ok(null);
//        }
//        return ResponseEntity.ok(response.get(0));
//    }

//    @PostMapping(path = "e2i")
//    ResponseEntity<List<String>> getIndicFromEnglish(@RequestBody List<String> texts, @RequestParam String target) {
//        List<String> response = translationService.translateFromEnglishToIndic(texts, target);
//        return ResponseEntity.ok(response);
//    }

    @PostMapping(path = "e2i")
    ResponseEntity<String> getIndicFromEnglish(@RequestBody String text, @RequestParam String target) {
        String response = translationService.translateFromEnglishToIndic(text, target);
        return ResponseEntity.ok(response);
    }
}
