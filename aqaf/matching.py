"""Explainable candidate matching; similarity never merges logical projects."""
import re
from difflib import SequenceMatcher

def name_features(a,b):
    def parts(value):
        value=re.sub(r'([a-z])([A-Z])',r'\1 \2',value)
        return re.findall('[a-z0-9]+',value.lower())[:64]
    aa,bb=parts(a),parts(b);x=' '.join(aa)[:256];y=' '.join(bb)[:256]
    ta,tb=set(aa),set(bb);token=2*len(ta&tb)/max(1,len(ta)+len(tb))
    ga={x[i:i+2] for i in range(len(x)-1)};gb={y[i:i+2] for i in range(len(y)-1)}
    bigram=2*len(ga&gb)/max(1,len(ga)+len(gb))
    previous=list(range(len(y)+1))
    for i,c in enumerate(x,1):
        current=[i]
        for j,d in enumerate(y,1):current.append(min(current[-1]+1,previous[j]+1,previous[j-1]+(c!=d)))
        previous=current
    edit=1-previous[-1]/max(1,len(x),len(y))
    generic=ta<= {'app','src','project','main','test','copy'} or tb<= {'app','src','project','main','test','copy'}
    return {'token_dice':round(token,4),'bigram_dice':round(bigram,4),'normalized_edit':round(edit,4),
            'sequence':round(SequenceMatcher(None,x,y).ratio(),4),'generic_name':generic,
            'interpretation':'Name similarity is candidate evidence only; compare selected source and config.'}
