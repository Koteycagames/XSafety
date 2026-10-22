import { SIGNATURES, LEVEL_NUM, SUSPICIOUS_WORDS } from "./signatures.js";

const MAGIC = [
 [/^MZ/, "PE/EXE-DLL"], [/^PK\x03\x04/, "ZIP/Office"], [/^Rar!/, "RAR"], [/^\x37\x7A\xBC\xAF/, "7Z"],
 [/^\x1f\x8b/, "GZIP"], [/^\xff\xd8\xff/, "JPEG"], [/^\x89PNG/, "PNG"], [/^%PDF/, "PDF"], [/^\x7fELF/, "ELF"]
];
function entropy(bytes){ const f=new Array(256).fill(0); bytes.forEach(b=>f[b]++); let e=0; for(const c of f){ if(!c)continue; const p=c/bytes.length; e-=p*Math.log2(p);} return e; }
function extractStrings(bytes, min=4){
  let out=[], cur="";
  for(const b of bytes){ if(b>=32&&b<127){cur+=String.fromCharCode(b);} else { if(cur.length>=min)out.push(cur); cur=""; } }
  if(cur.length>=min)out.push(cur); return out.join("\n");
}
async function scanZip(buf, add){
  // Парсим имена файлов внутри ZIP + пробуем распаковать (deflate) и просканировать содержимое
  try{
    const dv=new DataView(buf); let eocd=-1;
    for(let i=buf.byteLength-22;i>=0;i--){ if(dv.getUint32(i,true)===0x06054b50){eocd=i;break;} }
    if(eocd<0) return; const count=dv.getUint16(eocd+10,true); let off=dv.getUint32(eocd+16,true);
    const names=[];
    for(let n=0;n<count && off<buf.byteLength-46;n++){
      if(dv.getUint32(off,true)!==0x02014b50) break;
      const method=dv.getUint16(off+10,true), csize=dv.getUint32(off+20,true);
      const nlen=dv.getUint16(off+28,true), elen=dv.getUint16(off+30,true), clen=dv.getUint16(off+32,true);
      const name=new TextDecoder().decode(new Uint8Array(buf,off+46,nlen)); names.push(name);
      const lho=dv.getUint32(off+42,true);
      const lnlen=dv.getUint16(lho+26,true), lelen=dv.getUint16(lho+28,true);
      const dataStart=lho+30+lnlen+lelen;
      const raw=new Uint8Array(buf,dataStart,csize);
      if(/\.(exe|dll|bat|ps1|vbs|js|jar|scr|com)$/i.test(name)) add(30,"Опасное вложение в архиве",name);
      if(method===8 && "DecompressionStream" in window && csize<5_000_000){
        try{ const ds=new DecompressionStream("deflate-raw"); const out=new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(ds)).arrayBuffer());
             const inner=extractStrings(out); for(const s of SIGNATURES){ if(s.re.test(inner)) add(Math.min(s.w,25),"Скрытая сигнатура в ZIP",`${name}: ${s.cat}`);} }catch{}
      }
      off+=46+nlen+elen+clen;
    }
    if(names.length) add(5,"Содержимое архива", names.slice(0,20).join(", "));
  }catch{}
}

export async function scanFile(file, modelId, onProgress=()=>{}){
  const level = LEVEL_NUM[modelId];
  const buf = await file.arrayBuffer(); const bytes = new Uint8Array(buf);
  const findings=[]; const add=(score,cat,detail)=>findings.push({score,cat,detail:String(detail).slice(0,240)});
  onProgress(15);
  // Текст + строки из бинаря (Lite/Pro достают строки даже из dll/jar/архивов)
  let text = "";
  try{ text = new TextDecoder("utf-8",{fatal:false}).decode(bytes); }catch{}
  if(level>=3) text += "\n" + extractStrings(bytes);
  onProgress(35);
  // Сигнатуры по уровню модели: 1 — только базовые, Pro — все
  for(const s of SIGNATURES){ if(s.min<=level && s.re.test(text)) add(s.w, s.cat, (text.match(s.re)||[])[0]); }
  onProgress(55);
  // Энтропия: высокая = шифрование/упаковка. Pro видит точнее, v1 — почти нет.
  const ent = entropy(bytes.slice(0, 200000));
  if(level>=2 && ent>7.2) add(level>=4?30:18,"Высокая энтропия (шифрование/упаковка)",`entropy=${ent.toFixed(2)}`);
  if(level>=4 && ent>6.5 && ent<=7.2) add(10,"Повышенная энтропия",`entropy=${ent.toFixed(2)}`);
  // Зашифрованные/закодированные вставки
  const b64 = text.match(/[A-Za-z0-9+/]{200,}={0,2}/g);
  if(level>=3 && b64) add(level>=4?28:18,"Длинные Base64-вставки (возможен скрытый пейлоад)",`${b64.length} блок(ов)`);
  if(level>=4){ // XOR/hex-паттерны и двойные расширения — только Pro
    if(/(\\x[0-9a-fA-F]{2}){16,}/.test(text)) add(25,"Hex-shellcode","длинная \\x-последовательность");
    if(/\b(xor|bxor)\b/i.test(text) && /loop|for|while/i.test(text)) add(20,"XOR-цикл расшифровки","");
    if(/\.[a-z]{2,4}\.(exe|scr|bat|js|vbs)$/i.test(file.name)) add(25,"Двойное расширение файла",file.name);
    for(const [re,label] of MAGIC){ if(re.test(text.slice(0,8)) && !file.name.toLowerCase().endsWith(label.toLowerCase().split("/")[0])) add(8,"Магические байты",label); }
  }
  for(const w of SUSPICIOUS_WORDS){ if(level>=2 && file.name.toLowerCase().includes(w)) add(12,"Подозрительное имя файла",w); }
  if(/zip|rar|7z|tar|gz|jar$/.test(file.name.split(".").pop().toLowerCase()) && level>=3) await scanZip(buf, add);
  onProgress(90);
  const score = Math.min(100, findings.reduce((a,f)=>a+f.score,0));
  const verdict = score>=50 ? "ОПАСНО" : score>=20 ? "ПОДОЗРИТЕЛЬНО" : "ЧИСТО";
  onProgress(100);
  return { fileName:file.name, size:file.size, model:modelId, score, verdict, entropy:+ent.toFixed(2),
           sha256: await sha256(buf), findings: findings.sort((a,b)=>b.score-a.score).slice(0,30), scannedAt: Date.now() };
}
async function sha256(buf){ try{ const h=await crypto.subtle.digest("SHA-256",buf); return [...new Uint8Array(h)].map(b=>b.toString(16).padStart(2,"0")).join(""); }catch{ return "n/a"; } }
