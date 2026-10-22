export const MODELS = {
  v1:   { id:"v1",   name:"XSafety 1",     desc:"Базовое сканирование .bat и .py" },
  v2:   { id:"v2",   name:"XSafety 2",     desc:"Скрипты: bat, py, js, vbs, vbe, hta" },
  lite: { id:"lite", name:"XSafety 3 Lite",desc:"Документы, архивы, jar, dll, PowerShell и др." },
  pro:  { id:"pro",  name:"XSafety 3 Pro", desc:"Максимальный анализ любых файлов" }
};

// requests = кол-во запросов, maxMB = макс. размер одного файла
export const PLANS = {
  default: { name:"Default", price:"Бесплатно", limits:{ v1:{requests:5, maxMB:10} } },
  pro:     { name:"Pro",     price:"Pro",       limits:{ v1:{requests:15,maxMB:30}, v2:{requests:10,maxMB:30}, lite:{requests:5, maxMB:30} } },
  premium: { name:"Premium", price:"Premium",   limits:{ v1:{requests:30,maxMB:50}, v2:{requests:25,maxMB:50}, lite:{requests:20,maxMB:50}, pro:{requests:15,maxMB:100} } }
};

export const MODEL_EXTS = {
  v1: ["bat","py"],
  v2: ["bat","py","js","vbs","vbe","hta"],
  lite: ["bat","py","js","vbs","vbe","hta","docm","dotm","xlsm","xltm","pptm","potm","ppsm",
         "doc","xls","ppt","zip","rar","7z","tar","gz","iso","img","vhd","vhdx","jar","pyw","dll",
         "jse","ps1","ps1xml","ps2","ps2xml","psc1","psc2"],
  pro: null // null = любой формат
};

export const extOf = name => (name.split(".").pop()||"").toLowerCase();
export function modelAllowsFile(modelId, fileName){
  const allowed = MODEL_EXTS[modelId];
  if (allowed === null) return true;
  return allowed.includes(extOf(fileName));
}
export function limitFor(planId, modelId){ return PLANS[planId]?.limits[modelId] || null; }
