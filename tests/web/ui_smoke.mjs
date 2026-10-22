/* Проверка интерфейса: app.js загружается в jsdom с заглушкой Firebase,
 * рендерит модели, тарифы со скидками, покупает тариф и сканирует файл.
 */
import { readFileSync } from "node:fs";
import { JSDOM } from "jsdom";

const dom = new JSDOM(readFileSync("index.html", "utf8"), {
  url: "https://koteycagames.github.io/XSafety/",
  pretendToBeVisual: true,
});
const { window } = dom;
window.HTMLElement.prototype.scrollIntoView = () => {};
globalThis.window = window;
globalThis.document = window.document;
globalThis.Node = window.Node;
globalThis.HTMLElement = window.HTMLElement;
globalThis.Event = window.Event;
globalThis.location = window.location;
globalThis.history = window.history;
globalThis.File = window.File;
globalThis.FileList = window.FileList;
globalThis.Blob = window.Blob;
globalThis.FileReader = window.FileReader;

const failures = [];
const check = (condition, message) => { if (!condition) failures.push(message); };

const firebase = await import("./stub-firebase.mjs");
await import("../../js/app.js");
await new Promise((resolve) => setTimeout(resolve, 20));

const $ = (selector) => window.document.querySelector(selector);

// 1. Гость видит форму входа.
check(!$("#authView").classList.contains("hidden"), "форма входа не показана");
check($("#userBar").classList.contains("hidden"), "навигация видна до входа");

// 2. Вход: загружается профиль Default.
firebase.signInForTest({ uid: "uid-1", email: "tester@gmail.com" });
await new Promise((resolve) => setTimeout(resolve, 50));

check(!$("#scanView").classList.contains("hidden"), "после входа не открылся сканер");
const cards = [...window.document.querySelectorAll(".model-card")];
check(cards.length === 4, `ожидалось 4 модели, найдено ${cards.length}`);
const locked = cards.filter((card) => card.classList.contains("locked"));
check(locked.length === 3, `на Default заблокированы 3 модели, найдено ${locked.length}`);
check(cards[0].textContent.includes("Осталось 10 из 10"), `нет лимита в карточке m1: ${cards[0].textContent}`);
check($("#refillTime").textContent.includes("ч"), "нет таймера обновления лимитов");

// 3. Тарифы: цены, зачёркнутые старые, проценты.
window.document.querySelector("#navPlans").click();
check(!$("#plansView").classList.contains("hidden"), "вкладка тарифов не открылась");
const plans = [...window.document.querySelectorAll("#plansGrid .plan")];
check(plans.length === 3, `ожидалось 3 тарифа, найдено ${plans.length}`);
const offers = [...window.document.querySelectorAll(".offer")];
check(offers.length === 6, `ожидалось 6 предложений, найдено ${offers.length}`);
const discounts = [...window.document.querySelectorAll(".discount")].map((node) => node.textContent);
for (const expected of ["−31%", "−40,7%", "−55,2%", "−12,5%", "−28,7%", "−0,06%"]) {
  check(discounts.includes(expected), `нет скидки ${expected}: ${discounts.join(" ")}`);
}
const crossed = [...window.document.querySelectorAll(".old")].map((node) => node.textContent.replace(/\s/g, " "));
check(crossed.some((text) => text.includes("2 900")), `нет зачёркнутой цены 2900: ${crossed.join(" | ")}`);
check(offers[1].textContent.includes("249"), "цена Pro за месяц не 249");

// 4. Покупка Pro (демо): лимиты и разблокировка моделей.
offers[0].click();
await new Promise((resolve) => setTimeout(resolve, 10));
check(!$("#modal").classList.contains("hidden"), "модалка покупки не открылась");
$("#modalOk").click();
await new Promise((resolve) => setTimeout(resolve, 60));
check($("#userPlan").textContent === "Pro", `тариф не переключился: ${$("#userPlan").textContent}`);
check(firebase.store.data.users["uid-1"].plan === "pro", "план не записан в базу");
const afterPurchase = [...window.document.querySelectorAll(".model-card")];
check(afterPurchase.filter((card) => card.classList.contains("locked")).length === 1, "на Pro должна остаться одна заблокированная модель");
check(afterPurchase[0].textContent.includes("Осталось 20 из 20"), "лимит m1 после покупки не 20");
check(afterPurchase[2].textContent.includes("Осталось 1 из 1"), "лимит 3 Lite на Pro не 1");

// 5. Сканирование BAT.
window.document.querySelector("#navScan").click();
const input = $("#fileInput");
const file = new window.File(["@echo off\nvssadmin delete shadows /all /quiet\n"], "evil.bat", { type: "text/plain" });
Object.defineProperty(input, "files", { value: [file], configurable: true });
input.dispatchEvent(new window.Event("change"));
$("#scanBtn").click();
await new Promise((resolve) => setTimeout(resolve, 400));
const resultText = $("#result").textContent;
check(resultText.includes("Опасно"), `вердикт не показан: ${resultText.slice(0, 120)}`);
check(resultText.includes("vssadmin") || resultText.includes("теневых"), "находка не отображена");
const usage = firebase.store.data.users["uid-1"].usage.m1;
check(usage && usage.count === 1, `счётчик не увеличился: ${JSON.stringify(usage)}`);

// 6. История.
window.document.querySelector("#navHistory").click();
await new Promise((resolve) => setTimeout(resolve, 80));
check($("#historyList").textContent.includes("evil.bat"), "история пуста");

if (failures.length) {
  console.error("✗ " + failures.join("\n✗ "));
  process.exit(1);
}
console.log("✓ UI smoke: 6 сценариев пройдены");
process.exit(0);
