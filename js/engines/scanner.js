import { SIGNATURES, LEVEL_NUM, SUSPICIOUS_WORDS } from "./signatures.js";

/* ================================================================
   XSafety Pipeline (не наивный текстовый поиск!):
   [файл] → MAGIC-bytes (тип НЕ по расширению) → ветвление:
     скрипты → деобфускация/нормализация (BAT ^, %VAR%, конкатенации
               строк, bracket-нотация) → AST-подобный анализ вызовов
               → авто-декодеры (Base64/Hex/char-массивы/XOR) → сигнатуры
     бинари  → PE-парсер (секции, энтропия секций, IAT-импорты, пакеры)
     архивы  → ZIP: лимит РАСПАКОВАННОГО размера, флаг шифрования,
               Zip-Slip, рекурсия; RAR/7Z: listing по строкам+честный статус
     Office  → ZIP-контейнер → vbaProject.bin (ASCII+UTF-16 строки VBA)
     PDF     → потоки/строки, JavaScript/OpenAction/Launch
   Уровни: v1 — база+BAT-нормализация, v2 — +фолдинг конкатенаций/вызовы,
   Lite — +декодеры, ZIP/Office/PDF, Pro — +PE/IAT, XOR-брут, всё.
================================================================ */
const td = new TextDecoder("utf-8", { fatal:false });
const INNOCENT = ["jpg","jpeg","png","gif","bmp","webp","pdf","txt","md","mp3","mp4","avi","wav"];
const DANGEROUS_EXTS = /\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|jar|scr|com|hta|msi|py|pyw)$/i;

function entropy(bytes){ const f=new Array(256).fill(0); for(const b of bytes)f[b]++; let e=0; for(const c of f){ if(!c)continue; const p=c/bytes.length; e-=p*Math.log2(p);} return e; }
function stringsAscii(bytes,min=4){ const out=[]; let cur=""; for(const b of bytes){ if(b>=32&&b<127)cur+=String.fromCharCode(b); else { if(cur.length>=min)out.push(cur); cur=""; } } if(cur.length>=min)out.push(cur); return out; }
function stringsUtf16(bytes,min=4){ const out=[]; let cur=""; for(let i=0;i+1<bytes.length;i+=2){ const c=bytes[i],h=bytes[i+1]; if(h===0&&c>=32&&c<127)cur+=String.fromCharCode(c); else { if(cur.length>=min)out.push(cur); cur=""; } } if(cur.length>=min)out.push(cur); return out; }
function detectMagic(b){
  if(b[0]===0x4D&&b[1]===0x5A) return "PE";
  if(b[0]===0x50&&b[1]===0x4B&&b[2]===3&&b[3]===4) return "ZIP";
  if(b[0]===0x52&&b[1]===0x61&&b[2]===0x72&&b[3]===0x21) return "RAR";
  if(b[0]===0x37&&b[1]===0x7A&&b[2]===0xBC&&b[3]===0xAF) return "7Z";
  if(b[0]===0x1F&&b[1]===0x8B) return "GZIP";
  if(b[0]===0x25&&b[1]===0x50&&b[2]===0x44&&b[3]===0x46) return "PDF";
  if(b[0]===0xD0&&b[1]===0xCF&&b[2]===0x11&&b[3]===0xE0) return "OLE";
  if(b[0]===0x7F&&b[1]===0x45&&b[2]===0x4C&&b[3]===0x46) return "ELF";
  if(b[0]===0xCA&&b[1]===0xFE&&b[2]===0xBA&&b[3]===0xBE) return "CLASS/JAR";
  return null;
}

/* ---------- 1.1 Нормализация скриптов ---------- */
function normalizeBat(t){
  let out=t.replace(/\^/g,""); // ^ в BAT — эскейп (снимаем ДО разбора set-переменных)
  const vars={};
  for(const m of out.matchAll(/^\s*set\s+(?:\/p\s+)?"?([A-Za-z_][\w]*)=([^"\r\n]*)/gim)) vars[m[1].toUpperCase()]=m[2].trim();
  for(let i=0;i<3;i++) out=out.replace(/%([A-Za-z_]\w*)%/g,(s,k)=>vars[k.toUpperCase()]??s);
  out=out.replace(/%([A-Za-z_]\w*):~[^%]*%/g,(s,k)=>vars[k.toUpperCase()]??s); // %VAR:~0,3% срезы — подставляем исходник
  return out;
}
function foldConcats(t){ // 'eva'+'l' / "po"+"wershell" / `a${'b'}c` → склеенные литералы
  let prev;
  do{ prev=t; t=t.replace(/(['"`])([^'"`\\\n]{0,200})\1\s*\+\s*(['"`])([^'"`\\\n]{0,200})\3/g,"$1$2$4$1"); }while(t!==prev);
  return t.replace(/\[\s*(['"])((?:(?!\1).){1,60})\1\s*\]/g,".$2"); // obj['eval'] → obj.eval
}
function normalizeScript(t, ext){
  let out=t;
  if(ext==="bat"||ext==="cmd") out=normalizeBat(out);
  out=foldConcats(out);
  out=out.replace(/String\.fromCharCode\s*\(([\d\s,]+)\)/gi,(s,n)=>{ try{ return "'"+n.split(",").map(x=>String.fromCharCode(+x)).join("")+"'"; }catch{ return s; } });
  out=out.replace(/chr\s*\(\s*(\d{1,3})\s*\)/gi,(s,n)=>"'"+String.fromCharCode(+n)+"'");
  return foldConcats(out);
}
// AST-подобный анализ: какие опасные функции РЕАЛЬНО вызываются (после нормализации)
const DANGEROUS_CALLS = [
 [/(\beval|\bexec|\bFunction)\s*\(/,35,"Вызов eval/exec/Function"], [/importlib\.import_module|__import__\s*\(/,35,"Динамический импорт (importlib/__import__)"],
 [/\bgetattr\s*\(/,25,"getattr — динамический доступ к функциям"], [/subprocess\.|os\.system|os\.popen|child_process|execSync|spawn\s*\(/,30,"Запуск внешних процессов"],
 [/WScript\.Shell|\.Run\s*\(|ShellExecute|CreateObject\s*\(/,30,"Запуск через Shell/CreateObject"],
 [/Invoke-Expression|\bIEX\b|DownloadString|DownloadFile|WebClient/,35,"PowerShell download-cradle / IEX"],
 [/atob\s*\(|Buffer\.from\s*\([^)]*['"]base64/,20,"Декодирование Base64 в рантайме"], [/powershell|cmd\.exe|mshta|wscript|cscript/i,10,"Вызов интерпретаторов/хостов"],
];

/* ---------- 1.2 Авто-декодеры ---------- */
function tryDecodePayloads(text, level, add, scanTextFn, ext=''){
  // Base64 (стандартный + URL-safe), рекурсивно до глубины 2
  const seen=new Set();
  const walk=(txt,depth)=>{
    if(depth>2) return;
    for(const m of txt.match(/[A-Za-z0-9+/=_-]{120,}/g)||[]){
      const clean=m.replace(/-/g,"+").replace(/_/g,"/"); if(clean.length%4===1||seen.has(clean)) continue; seen.add(clean);
      try{ const bin=atob(clean.padEnd(Math.ceil(clean.length/4)*4,"=")); const dec=td.decode(Uint8Array.from(bin,c=>c.charCodeAt(0)));
        if(/[\x20-\x7E]{20,}/.test(dec)){ add(level>=4?26:18,"Декодирован скрытый Base64-пейлоад",dec.slice(0,120)); scanTextFn(dec,`base64#${depth}`); walk(dec,depth+1); } }catch{}
    }
  };
  if(level>=3) walk(text,0);
  // Hex-строки
  for(const m of text.match(/(?:\\x[0-9a-fA-F]{2}){16,}|(?:\b[0-9a-fA-F]{2}[\s,;]){16,}[0-9a-fA-F]{2}/g)||[]){
    try{ const nums=m.match(/[0-9a-fA-F]{2}/g).map(h=>parseInt(h,16)); const dec=td.decode(new Uint8Array(nums));
      add(22,"Декодирован Hex-пейлоад",dec.slice(0,120)); scanTextFn(dec,"hex"); }catch{}
  }
  // Char-массивы: [char]101+[char]120... / chr() цепочки
  for(const m of text.match(/(?:\[char\]\d{1,3}\s*\+?\s*){5,}|(?:chr\(\d{1,3}\)\s*[+,]?\s*){5,}/gi)||[]){
    const nums=m.match(/\d{1,3}/g).map(Number); const dec=String.fromCharCode(...nums);
    add(24,"Декодирован char-массив",dec.slice(0,120)); scanTextFn(dec,"char[]");
  }
  if(level>=4){ // XOR-цикл: не только слово xor — любая побитовая расшифровка в цикле
    const isBat = (ext==="bat"||ext==="cmd");
    if(!isBat && /(for|while|foreach)[\s\S]{0,300}?(\bxor\b|bxor|-bxor|BitConverter|\w\s*\^=|\w+\[[^\]]+\]\s*\^\s*\w)/i.test(text)) add(26,"Цикл побитовой (XOR) расшифровки","");
    // Одно-байтный XOR-брут по длинным hex/base64-блобам: ищем читаемый ASCII
    for(const m of text.match(/[0-9a-fA-F]{80,}/g)||[]){ const raw=Uint8Array.from(m.match(/../g).map(h=>parseInt(h,16)));
      for(let k=1;k<256;k++){ const dec=td.decode(raw.map(b=>b^k)); if(/powershell|http|cmd|eval|MZ/i.test(dec)){ add(35,"XOR-пейлоад вскрыт перебором ключа",`key=0x${k.toString(16)} ${dec.slice(0,80)}`); scanTextFn(dec,"xor"); break; } } }
  }
}

/* ---------- 2. PE-парсер ---------- */
const INJECTION_APIS=["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtCreateThreadEx","QueueUserAPC","SetThreadContext","NtUnmapViewOfSection","VirtualProtect","CreateProcess","WinExec","ShellExecute","URLDownloadToFile","InternetOpen","HttpSendRequest","WSAStartup","GetProcAddress","LoadLibrary","IsDebuggerPresent","GetAsyncKeyState","SetWindowsHookEx","CryptEncrypt","BCryptEncrypt","RegSetValue","CreateService","OpenProcess"];
function parsePE(bytes, add, scanTextFn){
  const dv=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength); const out={imports:[]};
  try{
    const peOff=dv.getUint32(0x3C,true); if(peOff>bytes.length-24||dv.getUint32(peOff,true)!==0x4550) return out;
    const nSec=dv.getUint16(peOff+6,true), optSize=dv.getUint16(peOff+20,true), opt=peOff+24;
    const is64=dv.getUint16(opt,true)===0x20B, ddBase=opt+(is64?112:96);
    const impRva=dv.getUint32(ddBase+8,true);
    const secOff=opt+optSize, sections=[];
    const secName=o=>{ let s=""; for(let i=0;i<8;i++){ const c=bytes[o+i]; if(!c)break; s+=String.fromCharCode(c);} return s; };
    for(let i=0;i<nSec;i++){ const o=secOff+i*40; sections.push({name:secName(o), vsize:dv.getUint32(o+8,true), vaddr:dv.getUint32(o+12,true), rsize:dv.getUint32(o+16,true), roff:dv.getUint32(o+20,true)}); }
    for(const s of sections){
      if(/UPX|MPRESS|ASPack/i.test(s.name)) add(45,"Файл упакован пакером",s.name);
      if(/\.vmp|themida|vprotect/i.test(s.name)) add(45,"VMProtect/Themida-протектор",s.name);
      if(s.rsize>0){ const e=entropy(bytes.subarray(s.roff, Math.min(bytes.length,s.roff+s.rsize))); if(e>7.3) add(22,`Зашифрованная секция ${s.name}`,`entropy=${e.toFixed(2)}`); }
      if(s.vsize>s.rsize*3&&s.rsize>0) add(15,`Аномалия секции ${s.name}`,"virtual >> raw (признак пакера)");
    }
    const rva2off=rva=>{ for(const s of sections){ if(rva>=s.vaddr&&rva<s.vaddr+Math.max(s.vsize,s.rsize)) return s.roff+(rva-s.vaddr);} return 0; };
    const cstr=off=>{ let s=""; while(off<bytes.length&&bytes[off]){ s+=String.fromCharCode(bytes[off++]); if(s.length>260)break;} return s; };
    let descOff=rva2off(impRva), guard=0;
    while(descOff&&guard++<64){ const oft=dv.getUint32(descOff,true), nameRva=dv.getUint32(descOff+12,true), ft=dv.getUint32(descOff+16,true);
      if(!nameRva) break; const dll=cstr(rva2off(nameRva)); let thunk=rva2off(oft||ft); let g2=0;
      while(thunk&&g2++<512){ const val=is64?Number(dv.getBigUint32(thunk,true)):dv.getUint32(thunk,true); if(!val)break;
        if(is64?(dv.getBigUint32(thunk,true)&(1n<<63n))===0n:(val&0x80000000)===0){ const nm=cstr(rva2off(val)+2); if(nm) out.imports.push(nm); }
        thunk+=is64?8:4; }
      descOff+=20; }
    const hits=INJECTION_APIS.filter(a=>out.imports.some(i=>i.toLowerCase().startsWith(a.toLowerCase())));
    const injCore=["VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","OpenProcess"].filter(a=>hits.includes(a));
    if(injCore.length>=3) add(60,"IAT: классическая Process Injection",injCore.join(", "));
    else if(hits.length) add(Math.min(40,hits.length*9),"IAT: опасные импорты",hits.slice(0,10).join(", "));
    if(out.imports.length===0&&sections.length) add(18,"IAT пуста/скрыта","импорты прячутся — признак пакера/ручной загрузки");
    const overlay=sections.reduce((m,s)=>Math.max(m,s.roff+s.rsize),0);
    if(bytes.length-overlay>4096) add(20,"Overlay-данные после секций",`${bytes.length-overlay} байт вне PE-структуры`);
  }catch(e){ add(12,"PE-парсер: структура повреждена","возможно, файл специально искажён"); }
  return out;
}

/* ---------- 3. ZIP (жёсткий) ---------- */
const MAX_UNPACK=8*1024*1024; // лимит РАСПАКОВАННОГО, а не сжатого (анти zip-bomb)
async function inflateCapped(raw, method){
  if(method===0) return raw.subarray(0,MAX_UNPACK);
  if(method!==8||typeof DecompressionStream==="undefined") return null;
  const reader=new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks=[]; let total=0;
  while(true){ const {done,value}=await reader.read(); if(done)break; total+=value.length;
    if(total>MAX_UNPACK){ try{ await reader.cancel(); }catch{} return "TOO_BIG"; } chunks.push(value); }
  const out=new Uint8Array(total); let o=0; for(const c of chunks){ out.set(c,o); o+=c.length; } return out;
}
async function scanZip(buf, bytes, add, scanTextFn, level, depth=0){
  const dv=new DataView(buf); let eocd=-1;
  for(let i=buf.byteLength-22;i>=Math.max(0,buf.byteLength-66000);i--){ if(dv.getUint32(i,true)===0x06054b50){ eocd=i; break; } }
  if(eocd<0){ add(15,"ZIP: не найден каталог","архив повреждён или это не ZIP"); return; }
  const count=dv.getUint16(eocd+10,true); let off=dv.getUint32(eocd+16,true);
  const names=[];
  for(let n=0;n<count&&off<buf.byteLength-46;n++){
    if(dv.getUint32(off,true)!==0x02014b50) break;
    const flags=dv.getUint16(off+8,true), method=dv.getUint16(off+10,true), csize=dv.getUint32(off+20,true), usize=dv.getUint32(off+24,true);
    const nlen=dv.getUint16(off+28,true), elen=dv.getUint16(off+30,true), clen=dv.getUint16(off+32,true), lho=dv.getUint32(off+42,true);
    const name=td.decode(new Uint8Array(buf,off+46,nlen)); names.push(name);
    const encrypted=(flags&1)===1;
    if(encrypted) add(30,"Архив/файл защищён паролем",`${name} — содержимое НЕ проверено, вердикт не может быть «ЧИСТО»`);
    if(/(^|\/)\.\.(\/|$)|^[a-zA-Z]:\\|^\\/.test(name)) add(35,"Zip-Slip: выход за пределы папки",name);
    if(usize>0&&csize>0&&usize/csize>200&&usize>10_000_000) add(35,"Подозрение на ZIP-бомбу",`${name}: ${csize} → ${usize} байт`);
    if(DANGEROUS_EXTS.test(name)) add(28,"Опасное вложение в архиве",name);
    // Распаковка с капом — только если не зашифровано
    if(!encrypted&&level>=3&&depth<2&&csize<=MAX_UNPACK){
      try{ const lnlen=dv.getUint16(lho+26,true), lelen=dv.getUint16(lho+28,true);
        const raw=new Uint8Array(buf,lho+30+lnlen+lelen,lho+30+lnlen+lelen+csize<=buf.byteLength?csize:0);
        const inner=await inflateCapped(raw,method);
        if(inner==="TOO_BIG") add(35,"Распаковка остановлена: >8 МБ (защита от ZIP-бомбы)",name);
        else if(inner){ const innerStr=[...stringsAscii(inner),...stringsUtf16(inner)].join("\n"); scanTextFn(innerStr,`ZIP:${name}`);
          if(inner[0]===0x4D&&inner[1]===0x5A){ add(30,"В архиве спрятан EXE/DLL",name); if(level>=4) parsePE(inner,add,scanTextFn); }
          if(inner[0]===0x50&&inner[1]===0x4B&&depth<1) await scanZip(inner.buffer.slice(inner.byteOffset,inner.byteOffset+inner.byteLength),inner,add,scanTextFn,level,depth+1);
          if(/vbaProject\.bin$/i.test(name)) scanTextFn(innerStr,"VBA-макросы (vbaProject.bin)"); }
      }catch{ /* битый элемент — не молчим полностью: */ add(8,"ZIP: элемент не распаковался",name); }
    }
    off+=46+nlen+elen+clen;
  }
  if(names.length&&depth===0) add(4,"Содержимое архива",names.slice(0,20).join(", "));
  return names;
}

/* ---------- ГЛАВНЫЙ СКАН ---------- */
export async function scanFile(file, modelId, onProgress=()=>{}){
  const level=LEVEL_NUM[modelId], buf=await file.arrayBuffer(), bytes=new Uint8Array(buf);
  const ext=(file.name.split(".").pop()||"").toLowerCase();
  const findings=[]; const seenFind=new Set();
  const add=(score,cat,detail="")=>{ const k=cat.replace(/ \[.*\]$/,"")+"|"+detail; if(seenFind.has(k))return; seenFind.add(k); findings.push({score,cat,detail:String(detail).slice(0,240)}); };
  let minVerdict=0; // 1 = минимум ПОДОЗРИТЕЛЬНО (нельзя "ЧИСТО" при непроверяемости)
  const scanText=(txt,where="")=>{ if(!txt) return; for(const s of SIGNATURES){ if(s.min<=level&&s.re.test(txt)) add(s.w,where?`${s.cat} [${where}]`:s.cat,(txt.match(s.re)||[])[0]); } };
  onProgress(10);

  // --- Определение типа по MAGIC, а не расширению ---
  const magic=detectMagic(bytes);
  if(magic==="PE"&&INNOCENT.includes(ext)) add(60,"МАСКИРОВКА: исполняемый файл под видом безобидного",`MZ-структура, а расширение .${ext}`);
  else if(magic&&(magic==="ZIP"||magic==="RAR"||magic==="7Z")&&INNOCENT.includes(ext)) add(45,"МАСКИРОВКА: архив под видом безобидного файла",`${magic} при расширении .${ext}`);
  else if(magic==="PE"&&ext&&!["exe","dll","sys","scr","com","ocx","cpl"].includes(ext)&&level>=4) add(25,"Несоответствие типа и расширения",`внутри ${magic}, снаружи .${ext}`);
  onProgress(25);

  // --- Текст: raw + ASCII/UTF-16 строки (бинари, OLE, vbaProject) ---
  let text=td.decode(bytes);
  if(level>=3) text+="\n"+stringsAscii(bytes).join("\n")+"\n"+stringsUtf16(bytes).join("\n");
  const isScript=["bat","cmd","py","pyw","js","jse","vbs","vbe","hta","ps1","ps1xml","ps2","ps2xml","psc1","psc2"].includes(ext)||(!magic&&bytes.length<2_000_000);
  if(isScript){
    const raw=text; scanText(raw);
    if(level>=1){ const norm=normalizeBat(raw); if(norm!==raw){ add(0,"ℹ️ BAT: убраны ^ и развёрнуты переменные","нормалзация для анализа, не угроза"); scanText(norm,"после деобфускации BAT"); } }
    if(level>=2){ const norm=normalizeScript(raw,ext); scanText(norm,"после нормализации");
      for(const [re,w,cat] of DANGEROUS_CALLS){ if(re.test(norm)) add(w,cat,(norm.match(re)||[])[0]); }
      if(/['"`]\s*\+|fromCharCode|chr\s*\(|\[\s*['"]/.test(raw)) add(14,"Обфускация конкатенацией/кодами символов","имена функций склеены из кусков"); }
  } else scanText(text);
  onProgress(45);

  tryDecodePayloads(text, level, add, scanText, ext);
  onProgress(60);

  // --- Бинари: PE ---
  if(magic==="PE"&&level>=4){ const pe=parsePE(bytes,add,scanText); if(pe.imports.length) add(3,"PE импорты",pe.imports.slice(0,25).join(", ")); }
  else if(magic==="PE"&&level>=3){ if(/UPX0|UPX1|\.vmp|themida/i.test(text)) add(40,"Упакован/защищён протектором","глубокий PE-анализ доступен в XSafety 3 Pro"); scanText(text); }
  // --- Архивы ---
  const isOfficeZip=["docx","xlsx","pptx","docm","xlsm","pptm","dotm","xltm","potm","ppsm"].includes(ext);
  if((magic==="ZIP")&&level>=3){ const names=await scanZip(buf,bytes,add,scanText,level);
    if(isOfficeZip){ if(names.some(n=>/vbaProject\.bin/i.test(n))) add(20,"Документ содержит VBA-макросы","vbaProject.bin найден и просканирован"); if(names.some(n=>/(^|\/)oleObject|activeX/i.test(n))) add(25,"В документе встроены ActiveX/OLE-объекты",""); }
    if(names.some(n=>/vbaProject\.bin/i.test(n))) minVerdict=Math.max(minVerdict,0); }
  if((magic==="RAR"||magic==="7Z")&&level>=3){ minVerdict=Math.max(minVerdict,1);
    add(12,`${magic}: глубокая распаковка недоступна в браузере`,"выполнен анализ байт и имён; «ЧИСТО» для такого архива не выдаётся");
    const names=stringsAscii(bytes).filter(s=>DANGEROUS_EXTS.test(s)||/\.(zip|rar|7z)$/i.test(s));
    for(const n of names.slice(0,10)) add(25,`В ${magic} замечено опасное вложение (по строкам)`,n); scanText(text); }
  if(magic==="GZIP"&&level>=3){ add(15,"GZIP-поток","содержимое проверено по байтам без полной распаковки"); scanText(text); }
  // --- PDF ---
  if(magic==="PDF"&&level>=3){ for(const [re,w,c] of [[/\/JavaScript|\/JS\b/,30,"PDF: встроенный JavaScript"],[/\/OpenAction|\/AA\b/,22,"PDF: автодействие при открытии"],[/\/Launch|\/EmbeddedFile/,28,"PDF: запуск/вложенный файл"],[/\/RichMedia|\/SubmitForm/,15,"PDF: RichMedia/отправка форм"]]) if(re.test(text)) add(w,c,""); }
  // --- OLE (старый Office .doc/.xls) ---
  if(magic==="OLE"&&level>=3){ add(12,"OLE2-документ (старый Office)","макросы ищутся по ASCII+UTF-16 строкам"); if(/vba|macro|Auto_O|Workbook_Open/i.test(text)) add(28,"OLE: признаки VBA-макросов",""); scanText(text); }
  onProgress(80);

  // --- Энтропия / имена / прочее ---
  const ent=entropy(bytes.subarray(0,200000));
  if(level>=2&&ent>7.2) add(level>=4?28:18,"Высокая энтропия (шифрование/упаковка)",`entropy=${ent.toFixed(2)}`);
  if(level>=4&&ent>6.5&&ent<=7.2) add(10,"Повышенная энтропия",`entropy=${ent.toFixed(2)}`);
  if(/\.[a-z]{2,4}\.(exe|scr|bat|js|vbs)$/i.test(file.name)&&level>=4) add(25,"Двойное расширение файла",file.name);
  for(const w of SUSPICIOUS_WORDS){ if(level>=2&&file.name.toLowerCase().includes(w)) add(12,"Подозрительное имя файла",w); }
  onProgress(95);

  // --- Калибровка: обычный установщик != вирус ---
  // install/setup в имени + mkdir/copy/robocopy + чистка %TEMP%/%~dp0 и нет тяжёлых находок (>=30) => скидка
  const lowerAll=text.toLowerCase();
  let benignSignals=0;
  if(/install|setup|update|installer/.test(file.name.toLowerCase())) benignSignals++;
  if(/\b(mkdir|md|xcopy|robocopy|copy|move)\b/.test(lowerAll)) benignSignals++;
  if(/%temp%|%tmp%|%~dp0|%localappdata%\\temp/.test(lowerAll)) benignSignals++;
  if(/\b(echo|pause|exit\b|goto\b)/.test(lowerAll)) benignSignals++;
  const hasSevere=findings.some(f=>f.score>=30);
  let rawScore=findings.reduce((a,f)=>a+f.score,0);
  if(benignSignals>=2 && !hasSevere && rawScore>0){ add(0,"ℹ️ Признаки обычного установщика",`сигналов: ${benignSignals}, тяжёлых находок нет — применена скидка -20`); rawScore=Math.max(0,rawScore-20); }
  const score=Math.min(100,rawScore);
  let verdict=score>=50?"ОПАСНО":score>=20?"ПОДОЗРИТЕЛЬНО":"ЧИСТО";
  if(verdict==="ЧИСТО"&&minVerdict>=1) verdict="ПОДОЗРИТЕЛЬНО";
  onProgress(100);
  return { fileName:file.name, size:file.size, model:modelId, score, verdict, entropy:+ent.toFixed(2), magic:magic||"unknown",
           sha256:await sha256(buf), findings:findings.sort((a,b)=>b.score-a.score).slice(0,30), scannedAt:Date.now() };
}
async function sha256(b){ try{ const h=await crypto.subtle.digest("SHA-256",b); return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,"0")).join(""); }catch{ return "n/a"; } }
