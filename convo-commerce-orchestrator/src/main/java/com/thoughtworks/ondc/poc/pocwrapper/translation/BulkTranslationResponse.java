package com.thoughtworks.ondc.poc.pocwrapper.translation;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class BulkTranslationResponse {

    private List<String> translatedText;

}
