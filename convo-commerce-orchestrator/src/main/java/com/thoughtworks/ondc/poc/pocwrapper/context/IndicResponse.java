package com.thoughtworks.ondc.poc.pocwrapper.context;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class IndicResponse {
    private String input;
    private String result;
}