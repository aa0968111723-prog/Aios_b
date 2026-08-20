/**
 * 檢查過濾。
 *
 * src/core/types.ts 的 Category 註解寫著「決定 `--only` 能篩什麼」，但 `--only` 從來沒有被實作。
 * 少了它，出事當下想確認「剛剛那一項到底修好了沒」，唯一的辦法是整輪重跑——而完整輪跑含三端探測
 * 與瀏覽器頁面測試，慢到沒有人願意在排查中途等它。結果是最需要這套系統的時刻，大家改回肉眼掃 log，
 * 檢測系統被繞過。能只重跑一項，這套工具才進得了排查流程。
 *
 * 但過濾帶著一個必須被正面處理的風險：**被篩掉的檢查在報告上看起來會跟「沒問題」一模一樣。**
 * 一份只跑了 cors 的報告若沒有交代其餘十幾項去哪了，讀的人會把它當成完整檢測——那是這套系統最不能
 * 容忍的假綠燈。所以這個模組不只回答「誰留下」，也把「誰被篩掉」原樣交還給呼叫端
 * （`partitionChecks` 的 excluded），讓那些檢查以「跳過＋原因」的形式留在報告裡。
 * 跳過不等於通過——這條規則不因為跳過是使用者自己要求的而放寬，畢竟讀報告的人通常不是下指令的人。
 *
 * 另一個要正面擋的失誤是打錯字：`--only secuirty` 會忠實地把每一項都篩掉，然後產出一份零發現、
 * 外觀完全正常的報告。`unknownTokens` 就是為此存在——沒有對應到任何檢查的 token 必須當場說出來。
 *
 * 本檔不碰網路也不碰檔案系統，全部是純函式，因此整套過濾規則都能離線測試。
 */
import type { Category } from "./types.js";

/** 一組過濾條件。兩份清單都是正規化過的 token（見 `parseFilter`）。 */
export interface CheckFilter {
  /** 非空時，只有命中其中一個 token 的檢查會執行；空陣列代表「不限制」。 */
  only: string[];
  /** 命中其中一個 token 的檢查一律不執行，且優先於 `only`。 */
  skip: string[];
}

/**
 * 可被過濾的對象：一項檢查的名字與它的面向。
 *
 * 刻意只要這兩個欄位而不是整個 PlannedCheck，這樣 runner 的計畫項目與跑完的 CheckResult
 * 都能直接餵進來——報告層要把被篩掉的檢查列成跳過時，手上拿的正是後者。
 */
export interface FilterTarget {
  name: string;
  category: Category;
}

/** token 與檢查名一律用同一套正規化比對，否則「有沒有大寫」會變成判定的一部分。 */
const normalize = (value: string): string => value.trim().toLowerCase();

/**
 * 把一份 token 清單收斂成「實際會生效的樣子」：正規化、丟掉空 token、去重。
 *
 * 這支刻意被**每一個讀 filter 的函式**共用，而不是只在 `parseFilter` 裡做一次。理由是空 token 會
 * 製造這個模組最不能容忍的那種失敗：`{ only: ["  "] }` 若照字面解讀成「有指定 only」，每一項檢查
 * 都不命中而被整批篩掉，產出一份零發現、外觀完全正常的報告；偏偏那個 token 印出來是一片空白，
 * 連 `unknownTokens` 都沒有東西可以指著說「這個沒對應到」。沒有人會懷疑那份報告。
 * 收斂之後，這種輸入等同「沒有指定」——保守解是全部照跑：寧可多跑幾項，也不要靜默地什麼都不跑。
 *
 * 順帶讓判定不再取決於呼叫端有沒有先走過 `parseFilter`：同一個字串走哪條路都得到同一個結論。
 */
function effective(tokens: string[]): string[] {
  const out: string[] = [];
  for (const raw of tokens) {
    const token = normalize(raw);
    if (token.length === 0) continue;
    if (!out.includes(token)) out.push(token);
  }
  return out;
}

/**
 * 逗號分隔字串 → token 陣列。
 *
 * 尾逗號（`--only cors,`）會切出一個空字串，正是上面 `effective` 要擋掉的東西——
 * 使用者不會覺得自己多打了一個逗號，只會覺得工具壞了。
 */
const tokenize = (value: string | undefined): string[] => effective(value ? value.split(",") : []);

/**
 * 解析 CLI 給的兩個字串。
 *
 * 去空白、轉小寫、去重，三件事的理由是同一個：終端機打進來的東西不會乾淨
 * （`--only "cors, CORS,"` 是很正常的輸入），而每多一種寫法不被接受，就多一次
 * 「我明明有篩，怎麼什麼都沒跑」的困惑。這種困惑最後不會變成一張工單，只會變成
 * 「這工具不好用」然後沒人再開。
 */
export function parseFilter(only: string | undefined, skip: string | undefined): CheckFilter {
  return { only: tokenize(only), skip: tokenize(skip) };
}

/**
 * 這項檢查在這組條件下要不要執行。
 *
 * token 同時比對檢查名（`cors`、`auth-gate`）與分類名（`security`、`monitoring`），兩種粒度共用
 * 一個旗標：拆成 `--only-check` 與 `--only-category` 只會讓人記錯該用哪個，而兩者的命名空間本來
 * 就不重疊，混在一起不產生歧義。
 *
 * 比對是完全相同，不做前綴或包含：`--skip auth` 不會順手把 auth-gate 關掉。抑制清單那邊已經寫過
 * 同一個理由——會篩掉什麼必須一眼看得出來，看不出來的過濾遲早會多蓋掉一項而沒有人發現。
 *
 * skip 優先於 only 是刻意的：`--only security --skip cors` 讀起來就是「資安那組，但別碰 cors」。
 * 反過來讓 only 贏，會使 skip 在兩者並用時完全失效，而使用者只會以為自己排除掉了。
 *
 * 兩邊都在比對前正規化，不假設 filter 一定出自 `parseFilter`：判定結果不該取決於呼叫端有沒有
 * 先走過某一支函式。
 */
export function matchesFilter(target: FilterTarget, filter: CheckFilter): boolean {
  const identities = [normalize(target.name), normalize(target.category)];
  const hits = (tokens: string[]): boolean => tokens.some((token) => identities.includes(token));

  // 兩份清單都先收斂：只由空白組成的 only 會被當成「沒有指定」而留下全部，
  // 而不是把每一項都篩掉再讓呼叫端拿著一份空報告去以為自己驗過了。
  const only = effective(filter.only);
  if (hits(effective(filter.skip))) return false;
  if (only.length === 0) return true;
  return hits(only);
}

/**
 * 依過濾條件把檢查分成兩堆。
 *
 * 回傳 excluded 而不是只回留下的那堆，是這個模組存在的重點：呼叫端有義務把被篩掉的檢查以
 * 「跳過＋原因」寫進報告。少了這一半，報告會宣稱「本次檢查全數通過」，而事實是其中大部分
 * 根本沒有執行過。
 *
 * 兩堆各自維持輸入順序，且必然不重不漏（`kept.length + excluded.length === items.length`）——
 * 報告的總數要對得起來，對不起來的計數會讓讀者開始不相信整份報告。
 */
export function partitionChecks<T extends FilterTarget>(
  items: T[],
  filter: CheckFilter,
): { kept: T[]; excluded: T[] } {
  const kept: T[] = [];
  const excluded: T[] = [];
  for (const item of items) {
    if (matchesFilter(item, filter)) kept.push(item);
    else excluded.push(item);
  }
  return { kept, excluded };
}

/**
 * 沒有對應到任何檢查的 token。
 *
 * 這是整個模組最重要的一支。`--only secuirty` 少打一個字母，過濾會忠實地把每一項都篩掉，然後產出
 * 一份零發現、外觀完全正常的報告——那是最惡劣的假綠燈：使用者以為自己驗過了，而其實什麼都沒驗。
 * 呼叫端拿到非空結果時應該當場警告（並可用 `KNOWN_CATEGORIES` 附上可填的分類），而不是照跑。
 *
 * 判準刻意是「有沒有對應到這一輪的任何檢查」，而不是「是不是合法的分類名」：`--only a11y` 配上
 * scan 指令（那一輪根本不含 a11y）拼字完全正確，但結果同樣是什麼都不會跑，使用者同樣需要被告知。
 *
 * only 與 skip 都檢查。打錯的 skip token 危害小得多（它只是沒生效），但「我明明排除了它，
 * 為什麼還在報告裡」同樣是一次白費的排查。
 */
export function unknownTokens(filter: CheckFilter, known: FilterTarget[]): string[] {
  const available = new Set<string>();
  for (const target of known) {
    available.add(normalize(target.name));
    available.add(normalize(target.category));
  }

  // 收斂過的 token 才拿來比對：空 token 不列（印出來是一片空白，等於沒講），
  // 重複的只列一次——一份把同一個錯字報三遍的警告，會讓人開始略過整行警告。
  return effective([...filter.only, ...filter.skip]).filter((token) => !available.has(token));
}

/**
 * 一行人話摘要，給終端與報告抬頭用。
 *
 * 沒有過濾時回空字串，讓呼叫端能直接 `if (line) print(line)`：這是唯一一種「什麼都不說」算誠實的
 * 情形——沒有過濾的報告本來就涵蓋全部。
 *
 * 回傳的是一段**可以嵌進別人句子裡的片語**（`只執行 health；略過 cors`），不是一個完整句子，也不
 * 自帶「檢查過濾：」之類的抬頭。這不是排版潔癖：呼叫端拿它去組自己的句子，cli.ts 就有兩處
 * （`檢查範圍：X` 與被過濾檢查的跳過理由 `依 X 排除，本輪未執行——未執行不等於通過。`）。
 * 自帶抬頭會變成「檢查範圍：檢查過濾：…」的疊字，自帶整句則會讓後者的句法整個崩掉——而那句話會
 * 原樣寫進每一個被過濾檢查的 skippedReason，出現在 console／markdown／html／junit 全部輸出裡。
 * 讀者看到語意不通的字串，第一個結論不會是「這裡有個排版問題」，而是「這份報告不太可靠」。
 *
 * 「未執行不等於通過」的提醒不放在這裡，是因為它屬於框住這段片語的那個句子：cli.ts 兩處各自都寫了，
 * 四個報告層也各自印了自己的涵蓋範圍告示。同一行裡重複兩次的提醒不會讓人更警覺，只會被當成雜訊。
 *
 * token 用收斂過的版本：摘要必須跟實際判定完全一致。摘要寫「只執行 cors、cors」或印出沒生效的空白
 * token，讀者就無法用這行字回推「這份報告到底涵蓋了什麼」——而這行字通常是他唯一的線索。
 */
export function describeFilter(filter: CheckFilter): string {
  const only = effective(filter.only);
  const skip = effective(filter.skip);
  const parts: string[] = [];
  if (only.length > 0) parts.push(`只執行 ${only.join("、")}`);
  if (skip.length > 0) parts.push(`略過 ${skip.join("、")}`);
  // 分隔用「；」與報告層的涵蓋範圍告示一致：同一件事在不同輸出上長得一樣，讀者才不會以為是兩件事。
  return parts.join("；");
}

const CATEGORY_LIST = ["security", "availability", "page", "a11y", "integrity", "monitoring"] as const;

/**
 * 編譯期守衛：Category 日後新增成員卻忘了補進上面的清單時，這一行會編譯失敗
 * （漏列時 Exclude 不再是 never，`true` 就填不進去）。
 *
 * 少列一個分類不會弄壞任何執行期行為，只會讓「可用的分類有哪些」這則提示少一項——
 * 正是那種永遠不會有人發現的錯誤，所以交給編譯器盯著。
 */
const _allCategoriesListed: Exclude<Category, (typeof CATEGORY_LIST)[number]> extends never ? true : never = true;

/**
 * 所有檢測面向，供呼叫端印出「可以填哪些分類」。
 *
 * 使用者被告知 token 無效之後，下一個問題必然是「那有哪些可以填」；答不出來的錯誤訊息
 * 等於沒有錯誤訊息。聯集型別在執行期沒有值可以列舉，只能手寫，完整性由上面的守衛顧著。
 */
export const KNOWN_CATEGORIES: readonly Category[] = CATEGORY_LIST;
