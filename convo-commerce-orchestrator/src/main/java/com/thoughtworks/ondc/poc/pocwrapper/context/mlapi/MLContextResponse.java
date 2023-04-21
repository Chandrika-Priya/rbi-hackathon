package com.thoughtworks.ondc.poc.pocwrapper.context.mlapi;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class MLContextResponse {

    private NextStep nextStep;
    private List<Map<String, String>> data;

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    public static class NextStep {

        private String message;
        private List<Alternates> alternates;

        @Getter
        @Setter
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Alternates {

            private String message;
            private BigDecimal confidence;

        }

    }

}