from fairseq import checkpoint_utils, distributed_utils, options, tasks, utils
from inference.engine import Model


class Translate:
    def __init__(self, model_base_dir):
        self.indic2en_model = Model(expdir=model_base_dir+"/indic-en")
        self.en2indic_model = Model(expdir=model_base_dir+"/en-indic")
        print("Initializing Translate class")

    def translate_indic_to_english(self, language, sentence):
        sents = [sentence]
        trans_sents = self.indic2en_model.batch_translate(sents, language, "en")
        return trans_sents[0]
    
    def english_to_indic(self, language, sentences):
        #sents = [sentence]
        trans_sents = self.en2indic_model.batch_translate(sentences, "en", language)
        return trans_sents

