"""Bounded voice synthetic-speech training for Cyber Guard.

Input: datasets/voice/voice_manifest.csv with columns path,label.
Labels: 0/real/bonafide/human or 1/spoof/fake/ai/synthetic.
Default: 500 balanced audio files (250 real + 250 spoof).

This is a lightweight development classifier. The existing voice API can be
integrated with this artifact after validation on held-out ASVspoof samples.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib, librosa, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/"datasets"/"voice"
MODELS=ROOT/"trained_models"
RESULTS=ROOT/"training_results"

def normalize_label(v):
    s=str(v).lower().strip()
    return int(s in {"1","spoof","fake","ai","synthetic","deepfake"} or "spoof" in s or "synthetic" in s or "fake" in s)

def features(path):
    y,sr=librosa.load(path,sr=16000,mono=True,duration=8.0)
    if len(y)<sr: y=np.pad(y,(0,sr-len(y)))
    mfcc=librosa.feature.mfcc(y=y,sr=sr,n_mfcc=20)
    delta=librosa.feature.delta(mfcc)
    arrays=[mfcc,delta,librosa.feature.rms(y=y),librosa.feature.zero_crossing_rate(y),
            librosa.feature.spectral_centroid(y=y,sr=sr),
            librosa.feature.spectral_bandwidth(y=y,sr=sr),
            librosa.feature.spectral_rolloff(y=y,sr=sr),
            librosa.feature.spectral_flatness(y=y)]
    f0=librosa.yin(y,fmin=70,fmax=400,sr=sr,frame_length=1024)
    f0=f0[np.isfinite(f0)]
    out=[]
    for a in arrays:
        a=np.asarray(a,dtype=np.float32).ravel()
        out += [float(np.mean(a)),float(np.std(a)),float(np.min(a)),float(np.max(a))]
    a=f0 if len(f0) else np.array([0.0])
    out += [float(np.mean(a)),float(np.std(a)),float(np.min(a)),float(np.max(a))]
    return np.nan_to_num(np.asarray(out,dtype=np.float32))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",type=Path,default=DATA/"voice_manifest.csv")
    p.add_argument("--max-samples",type=int,default=500)
    args=p.parse_args()
    if not args.manifest.exists():
        raise SystemExit(f"Create {args.manifest} with columns: path,label")
    df=pd.read_csv(args.manifest)
    if not {"path","label"}.issubset(df.columns):
        raise SystemExit("voice_manifest.csv needs path,label columns")
    df["label"]=df["label"].map(normalize_label)
    parts=[]; n=args.max_samples//2
    for label in (0,1):
        cls=df[df.label==label]
        parts.append(cls.sample(n=min(n,len(cls)),random_state=42))
    df=pd.concat(parts,ignore_index=True).sample(frac=1,random_state=42)
    print(f"[voice] selected {len(df):,} samples")
    X=[]; y=[]
    for i,row in enumerate(df.itertuples(index=False),1):
        path=Path(row.path)
        if not path.is_absolute(): path=ROOT/path
        try:
            X.append(features(str(path))); y.append(int(row.label))
        except Exception as exc:
            print(f"[skip] {path}: {exc}")
        if i%100==0: print(f"[voice] processed {i:,}/{len(df):,}")
    if len(set(y))<2: raise SystemExit("Both real/bonafide and spoof/fake classes are required.")
    X=np.vstack(X); y=np.asarray(y,dtype=np.int32)
    xtr,xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
    model=Pipeline([("scale",StandardScaler()),("classifier",RandomForestClassifier(
        n_estimators=300,max_depth=18,class_weight="balanced",n_jobs=4,random_state=42))])
    model.fit(xtr,ytr)
    proba=model.predict_proba(xte)[:,1]; pred=(proba>=.5).astype(int)
    MODELS.mkdir(parents=True,exist_ok=True); RESULTS.mkdir(parents=True,exist_ok=True)
    joblib.dump(model,MODELS/"voice_synthetic_rf.joblib")
    (RESULTS/"voice_synthetic_rf.json").write_text(json.dumps({
        "samples":len(y),"roc_auc":float(roc_auc_score(yte,proba)),
        "classification_report":classification_report(yte,pred,output_dict=True,zero_division=0)},indent=2),encoding="utf-8")
    print("[done] voice_synthetic_rf.joblib")

if __name__=="__main__": main()
