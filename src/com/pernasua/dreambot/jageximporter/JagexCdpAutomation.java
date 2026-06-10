package com.pernasua.dreambot.jageximporter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;

final class JagexCdpAutomation {
  private final BrowserSession browser;
  private final long humanCheckWaitMs;
  private final Consumer<String> log;
  private final RunControl control;

  JagexCdpAutomation(BrowserSession browser, long humanCheckWaitMs, Consumer<String> log) {
    this(browser, humanCheckWaitMs, log, RunControl.NONE);
  }

  JagexCdpAutomation(BrowserSession browser, long humanCheckWaitMs, Consumer<String> log,
      RunControl control) {
    this.browser = browser;
    this.humanCheckWaitMs = Math.max(0, humanCheckWaitMs);
    this.log = log == null ? ignored -> { } : log;
    this.control = control == null ? RunControl.NONE : control;
  }

  JagexOAuthClient.Callback completeAuth(JagexOAuthClient.AuthRequest request, String email,
      String password, String otpSecret) throws Exception {
    control.checkpoint();
    browser.prepareAuthRequest(request);
    boolean nativeJcefNavigation = browser.engine == BrowserEngine.JCEF;
    if (nativeJcefNavigation) {
      browser.navigate(request.url);
      sleep(6_000);
    }
    try (CdpClient cdp = openPage()) {
      if (!request.referrer.isEmpty()) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        headers.put("Referer", request.referrer);
        cdp.setExtraHttpHeaders(headers);
      }
      if (!nativeJcefNavigation) {
        cdp.navigate(request.url);
      }
      sleep(800);
      long totalWaitMs = Math.max(420_000L, humanCheckWaitMs + 180_000L);
      long deadline = System.currentTimeMillis() + totalWaitMs;
      boolean emailFilled = false;
      boolean passwordFilled = false;
      boolean codeFilled = false;
      boolean humanLogged = false;
      String lastAction = "";

      while (System.currentTimeMillis() < deadline) {
        control.checkpoint();
        State state = readState(cdp);
        JagexOAuthClient.Callback callback = callback(state, cdp.observedUrls(), request.state);
        if (callback != null) {
          return finishAuth(cdp, callback);
        }
        if (looksLikeOAuthCallback(state.href)) {
          lastAction = "waiting for OAuth callback state";
          sleep(650);
          continue;
        }

        String text = state.text.toLowerCase(Locale.ROOT);
        if (state.href.contains("error=") || matches(text, "invalid_request|oauth.*error|redirect_uri")) {
          throw new IllegalStateException("Jagex OAuth error page: " + brief(state.text));
        }
        if (isCookieNotice(text)) {
          String clicked = clickText(cdp, Arrays.asList(
              "use necessary cookies only",
              "allow all cookies",
              "accept all",
              "accept",
              "confirm choices",
              "save choices",
              "reject all"));
          if (!clicked.isEmpty()) {
            lastAction = "dismissed cookie notice";
            sleep(600);
            continue;
          }
        }
        if (matches(text, "technical difficulties|try again later|temporarily unavailable|service unavailable")) {
          throw new TemporaryOAuthException("Jagex temporary OAuth page: " + brief(state.text));
        }
        if (isAccountLocked(text)) {
          throw new TerminalAuthException("account_locked", "Jagex reported the account is locked");
        }
        if (isInvalidCredentials(text)) {
          throw new TerminalAuthException("invalid_credentials", "Jagex rejected the email or password");
        }
        if (codeFilled && isRejectedVerificationCode(text)) {
          throw new TerminalAuthException("invalid_otp_code", "Jagex rejected the authenticator code");
        }

        if (isCookieNotice(text)) {
          String clicked = clickText(cdp, Arrays.asList("use necessary cookies only", "allow all cookies"));
          if (!clicked.isEmpty()) {
            lastAction = "dismissed cookie notice";
            sleep(600);
            continue;
          }
        }

        if (matches(text, "are you a robot|verify you are human|security check|checking your browser")) {
          if (!humanLogged) {
            log.accept("browser is waiting on Jagex/Cloudflare human-check page");
            if (browser.engine == BrowserEngine.JCEF) {
              browser.reveal();
              log.accept("embedded JCEF browser was revealed for the human-check page");
            }
            humanLogged = true;
          }
          if (!waitPastHumanCheck(cdp, request.state)) {
            throw new IllegalStateException("human check did not clear within " + humanCheckWaitMs + "ms");
          }
          continue;
        }

        if (hasInput(state, "email") && !emailFilled) {
          fillFirst(cdp, Arrays.asList(
              "input[type='email']",
              "input[name='email']",
              "input[id*='email' i]",
              "input[autocomplete='email']",
              "input"), email);
          clickText(cdp, Arrays.asList("^continue$", "^log in$", "^next$", "^sign in$"));
          emailFilled = true;
          lastAction = "submitted email";
          sleep(800);
          continue;
        }

        if (hasInput(state, "password") && !passwordFilled) {
          fillFirst(cdp, Arrays.asList(
              "input[type='password']",
              "input[name='password']",
              "input[id*='password' i]",
              "input[autocomplete='current-password']"), password);
          clickText(cdp, Arrays.asList("^continue$", "^log in$", "^sign in$"));
          passwordFilled = true;
          lastAction = "submitted password";
          sleep(1_000);
          continue;
        }

        if (matches(text, "send a code to your email address|email verification")
            && !matches(text, "authenticator")) {
          throw new IllegalStateException("Jagex requested email verification instead of authenticator TOTP");
        }

        if (matches(text, "send a code to your email address|choose.*verification|two-step|two factor")
            && matches(text, "authenticator")) {
          String clicked = clickText(cdp, Arrays.asList("use your authenticator app", "authenticator app", "authenticator"));
          if (!clicked.isEmpty()) {
            lastAction = "selected authenticator";
            sleep(900);
            continue;
          }
        }

        if (codeInputReady(state) && !codeFilled) {
          Totp.Code code = freshTotp(otpSecret);
          fillCodeAndSubmit(cdp, code.value);
          codeFilled = true;
          lastAction = "submitted authenticator code";
          sleep(1_200);
          continue;
        }

        if (matches(text, "consent|allow|authorize|permission|continue|return to launcher|logging in to jagex launcher")) {
          String clicked = clickText(cdp, Arrays.asList(
              "^continue$",
              "^allow$",
              "^authorize$",
              "^confirm$",
              "^log in$",
              "return to launcher",
              "^open$"));
          if (!clicked.isEmpty()) {
            lastAction = "clicked " + clicked;
            sleep(900);
            continue;
          }
        }

        if (lastAction.isEmpty() && state.actions.isEmpty() && state.text.isEmpty()) {
          lastAction = "waiting for page";
        }
        sleep(650);
      }
      throw new IllegalStateException("timed out waiting for Jagex OAuth callback after " + lastAction);
    }
  }

  private CdpClient openPage() throws Exception {
    String ws;
    if (browser.engine == BrowserEngine.JCEF) {
      try {
        ws = CdpClient.pageWebSocket(browser.endpoint);
      } catch (Exception exception) {
        ws = CdpClient.newPage(browser.endpoint, "about:blank");
      }
    } else {
      try {
        ws = CdpClient.newPage(browser.endpoint, "about:blank");
      } catch (Exception exception) {
        ws = CdpClient.pageWebSocket(browser.endpoint);
      }
    }
    CdpClient cdp = CdpClient.connect(ws);
    cdp.send("Runtime.enable");
    cdp.send("Page.enable");
    cdp.send("Network.enable");
    return cdp;
  }

  private JagexOAuthClient.Callback finishAuth(CdpClient cdp, JagexOAuthClient.Callback callback) {
    try {
      cdp.setExtraHttpHeaders(new LinkedHashMap<>());
    } catch (RuntimeException ignored) {
      // The callback has already been captured; cleanup should not turn success into failure.
    }
    try {
      cdp.navigate("about:blank");
    } catch (RuntimeException ignored) {
      // Some callback URLs close or detach the page before cleanup can run.
    }
    browser.hide();
    return callback;
  }

  private JagexOAuthClient.Callback callback(State state, List<String> observedUrls, String expectedState) {
    ArrayList<String> candidates = new ArrayList<>();
    candidates.add(state.href);
    candidates.addAll(state.links);
    candidates.addAll(observedUrls);
    try {
      for (CdpClient.Target target : CdpClient.targets(browser.endpoint)) {
        candidates.add(target.url);
      }
    } catch (Exception ignored) {
      // The page's own state and the active CDP event buffer are still useful.
    }
    return JagexOAuthClient.findCallback(candidates, expectedState);
  }

  private boolean waitPastHumanCheck(CdpClient cdp, String expectedState) {
    long deadline = System.currentTimeMillis() + humanCheckWaitMs;
    long lastClick = 0L;
    while (System.currentTimeMillis() < deadline) {
      control.checkpoint();
      State state = readState(cdp);
      if (callback(state, cdp.observedUrls(), expectedState) != null) {
        return true;
      }
      if (!matches(state.text, "are you a robot|verify you are human|security check|checking your browser")) {
        return true;
      }
      long now = System.currentTimeMillis();
      if (now - lastClick >= 5_000L) {
        String clicked = clickHumanCheckProceed(cdp);
        if (!clicked.isEmpty()) {
          log.accept("clicked human-check " + clicked);
          lastClick = now;
          sleep(2_000);
          continue;
        }
        lastClick = now;
      }
      sleep(1_000);
    }
    return false;
  }

  private State readState(CdpClient cdp) {
    RuntimeException last = null;
    for (int attempt = 0; attempt < 30; attempt++) {
      try {
        return State.from(Json.asObject(cdp.evaluate(stateScript())));
      } catch (RuntimeException exception) {
        last = exception;
        String message = String.valueOf(exception.getMessage()).toLowerCase(Locale.ROOT);
        if (!(message.contains("execution context was destroyed")
            || message.contains("cannot find context")
            || message.contains("frame was detached"))) {
          throw exception;
        }
        sleep(350);
      }
    }
    throw last == null ? new IllegalStateException("could not read browser state") : last;
  }

  private boolean hasInput(State state, String regex) {
    Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    for (Map<String, Object> input : state.inputs) {
      String joined = Json.string(input.get("type")) + " "
          + Json.string(input.get("name")) + " "
          + Json.string(input.get("id")) + " "
          + Json.string(input.get("autocomplete")) + " "
          + Json.string(input.get("placeholder"));
      if (pattern.matcher(joined).find()) {
        return true;
      }
    }
    return false;
  }

  private boolean codeInputReady(State state) {
    String text = state.text.toLowerCase(Locale.ROOT);
    if (!matches(text, "authenticator|verification code|enter code|two-factor|two factor|totp")) {
      return false;
    }
    for (Map<String, Object> input : state.inputs) {
      String joined = (Json.string(input.get("type")) + " "
          + Json.string(input.get("name")) + " "
          + Json.string(input.get("id")) + " "
          + Json.string(input.get("autocomplete")) + " "
          + Json.string(input.get("placeholder"))).toLowerCase(Locale.ROOT);
      if (!joined.contains("email") && !joined.contains("password")) {
        return true;
      }
    }
    return false;
  }

  private Totp.Code freshTotp(String secret) {
    Totp.Code code = Totp.generate(secret);
    if (code.remainingSeconds < 8) {
      log.accept("current TOTP code has only " + code.remainingSeconds
          + "s remaining; waiting for the next period before submitting");
      sleep((code.remainingSeconds + 2L) * 1000L);
      code = Totp.generate(secret);
    }
    log.accept("generated TOTP code; value hidden, period " + code.period + "s, "
        + code.remainingSeconds + "s remaining, counter " + code.counter);
    return code;
  }

  private void fillFirst(CdpClient cdp, List<String> selectors, String value) {
    Object result = cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const selectors=" + Json.stringify(selectors) + ";"
        + "const el=candidates(selectors)[0];"
        + "if(!el)return '';"
        + "el.scrollIntoView({block:'center',inline:'center'});"
        + "setValue(el," + Json.quote(value) + ");"
        + "return el.tagName;"
        + "})()");
    if (Json.string(result).isEmpty()) {
      throw new IllegalStateException("could not find visible input on Jagex login page");
    }
  }

  private String clickText(CdpClient cdp, List<String> patterns) {
    Map<String, Object> point = Json.asObject(cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const patterns=" + Json.stringify(patterns) + ";"
        + "const elements=candidates(['button','input[type=\"submit\"]','a','[role=\"button\"]','label','div','span']);"
        + "const actionable=(el)=>{let cur=el;while(cur&&cur!==document.body){"
        + "const tag=String(cur.tagName||'').toLowerCase();"
        + "const role=String(cur.getAttribute('role')||'').toLowerCase();"
        + "const cursor=getComputedStyle(cur).cursor;"
        + "if(tag==='button'||tag==='a'||tag==='label'||tag==='input'||role==='button'||cur.onclick||cursor==='pointer'||cur.tabIndex>=0)return cur;"
        + "cur=cur.parentElement;}return el;};"
        + "for(const source of patterns){const re=new RegExp(source,'i');"
        + "for(const el of elements){const text=normalize(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent);"
        + "if(!re.test(text))continue;const target=actionable(el);target.scrollIntoView({block:'center',inline:'center'});"
        + "const r=target.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2,text:text||target.tagName.toLowerCase()};}}"
        + "return null;"
        + "})()"));
    if (point.isEmpty()) {
      return "";
    }
    double x = Json.number(point.get("x")).doubleValue();
    double y = Json.number(point.get("y")).doubleValue();
    cdp.send("Input.dispatchMouseEvent", mouse("mouseMoved", x, y));
    cdp.send("Input.dispatchMouseEvent", mouse("mousePressed", x, y, "left", 1));
    cdp.send("Input.dispatchMouseEvent", mouse("mouseReleased", x, y, "left", 1));
    return Json.string(point.get("text"));
  }

  private String clickHumanCheckProceed(CdpClient cdp) {
    String clicked = clickHumanCheckProceedInContext(cdp, true);
    if (!clicked.isEmpty()) {
      return clicked;
    }
    try {
      for (CdpClient.Target target : CdpClient.targets(browser.endpoint)) {
        String targetText = (target.type + " " + target.title + " " + target.url).toLowerCase(Locale.ROOT);
        if (!"iframe".equalsIgnoreCase(target.type)
            || target.webSocketUrl.isEmpty()
            || !matches(targetText, "cloudflare|challenge|turnstile|captcha|human|verify")) {
          continue;
        }
        try (CdpClient frame = CdpClient.connect(target.webSocketUrl)) {
          frame.send("Runtime.enable");
          frame.send("Page.enable");
          frame.send("Network.enable");
          clicked = clickHumanCheckProceedInContext(frame, false);
          if (!clicked.isEmpty()) {
            return "iframe " + clicked;
          }
        } catch (RuntimeException exception) {
          log.accept("could not click human-check iframe target: " + brief(exception.getMessage()));
        }
      }
    } catch (Exception exception) {
      log.accept("could not inspect human-check iframe targets: " + brief(exception.getMessage()));
    }
    return "";
  }

  private String clickHumanCheckProceedInContext(CdpClient cdp, boolean includeIframes) {
    Map<String, Object> point = Json.asObject(cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const textPatterns=[" + Json.quote("^proceed$") + "," + Json.quote("^continue$") + ","
        + Json.quote("^verify$") + "," + Json.quote("verify you are human") + ","
        + Json.quote("confirm you are human") + "," + Json.quote("i am human") + ","
        + Json.quote("i'm human") + "," + Json.quote("start verification") + "];"
        + "const actionable=(el)=>{let cur=el;while(cur&&cur!==document.body){"
        + "const tag=String(cur.tagName||'').toLowerCase();"
        + "const role=String(cur.getAttribute('role')||'').toLowerCase();"
        + "const cursor=getComputedStyle(cur).cursor;"
        + "if(tag==='button'||tag==='a'||tag==='label'||tag==='input'||role==='button'||cur.onclick||cursor==='pointer'||cur.tabIndex>=0)return cur;"
        + "cur=cur.parentElement;}return el;};"
        + "const elements=candidates(['button','input[type=\"submit\"]','input[type=\"button\"]','input[type=\"checkbox\"]','a','[role=\"button\"]','[role=\"checkbox\"]','label','div','span']);"
        + "for(const source of textPatterns){const re=new RegExp(source,'i');"
        + "for(const el of elements){const text=normalize(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent);"
        + "if(!re.test(text))continue;const target=actionable(el);target.scrollIntoView({block:'center',inline:'center'});"
        + "const r=target.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2,label:text||'control'};}}"
        + "const control=candidates(['input[type=\"checkbox\"]','[role=\"checkbox\"]','button','label']).find((el)=>{"
        + "const disabled=el.disabled||el.getAttribute('aria-disabled')==='true';return !disabled;});"
        + "if(control){const target=actionable(control);target.scrollIntoView({block:'center',inline:'center'});"
        + "const r=target.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2,label:'challenge control'};}"
        + (includeIframes ? ""
        + "const frame=Array.from(document.querySelectorAll('iframe')).filter(visible).find((iframe)=>{"
        + "const joined=[iframe.title,iframe.name,iframe.id,iframe.src,iframe.getAttribute('aria-label')].join(' ');"
        + "return /cloudflare|challenge|turnstile|captcha|human|verify/i.test(joined);});"
        + "if(frame){frame.scrollIntoView({block:'center',inline:'center'});const r=frame.getBoundingClientRect();"
        + "return {x:r.left+Math.min(38,Math.max(18,r.width*0.18)),y:r.top+r.height/2,label:'challenge frame'};}"
        : "")
        + (includeIframes ? "" :
        "const body=document.body;"
        + "if(body){const r=body.getBoundingClientRect();const width=Math.max(r.width,window.innerWidth||0);"
        + "const height=Math.max(r.height,window.innerHeight||0);if(width>0&&height>0){"
        + "return {x:r.left+Math.min(42,Math.max(20,width*0.18)),y:r.top+height/2,label:'challenge body'};}}"
        )
        + "return null;"
        + "})()"));
    if (point.isEmpty()) {
      return "";
    }
    double x = Json.number(point.get("x")).doubleValue();
    double y = Json.number(point.get("y")).doubleValue();
    cdp.send("Input.dispatchMouseEvent", mouse("mouseMoved", x, y));
    cdp.send("Input.dispatchMouseEvent", mouse("mousePressed", x, y, "left", 1));
    cdp.send("Input.dispatchMouseEvent", mouse("mouseReleased", x, y, "left", 1));
    return Json.string(point.get("label"));
  }

  private void fillCodeAndSubmit(CdpClient cdp, String code) {
    Map<String, Object> result = Json.asObject(cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const inputs=Array.from(document.querySelectorAll('input')).filter(visible)"
        + ".filter((input)=>!/email|password/i.test([input.type,input.name,input.id,input.autocomplete,input.placeholder].join(' ')));"
        + "const button=Array.from(document.querySelectorAll('button,input[type=\"submit\"],[role=\"button\"]')).filter(visible)"
        + ".find((el)=>/continue|verify|submit|log in|confirm/i.test(el.innerText||el.value||el.textContent));"
        + "if(inputs.length===0)return null;"
        + "const code=" + Json.quote(code) + ";"
        + "if(inputs.length>=code.length){for(let i=0;i<code.length;i++){setValue(inputs[i],code[i]);}}"
        + "else{setValue(inputs[0],code);}"
        + "const target=button||inputs[inputs.length-1];"
        + "target.scrollIntoView({block:'center',inline:'center'});"
        + "const r=target.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2,hasButton:Boolean(button)};"
        + "})()"));
    if (result.isEmpty()) {
      throw new IllegalStateException("could not find Jagex authenticator-code input");
    }
    double x = Json.number(result.get("x")).doubleValue();
    double y = Json.number(result.get("y")).doubleValue();
    cdp.send("Input.dispatchMouseEvent", mouse("mouseMoved", x, y));
    cdp.send("Input.dispatchMouseEvent", mouse("mousePressed", x, y, "left", 1));
    cdp.send("Input.dispatchMouseEvent", mouse("mouseReleased", x, y, "left", 1));
  }

  private Map<String, Object> mouse(String type, double x, double y) {
    return mouse(type, x, y, "", 0);
  }

  private Map<String, Object> mouse(String type, double x, double y, String button, int clickCount) {
    LinkedHashMap<String, Object> params = new LinkedHashMap<>();
    params.put("type", type);
    params.put("x", x);
    params.put("y", y);
    if (!button.isEmpty()) {
      params.put("button", button);
      params.put("clickCount", clickCount);
    }
    return params;
  }

  private String stateScript() {
    return "(() => {"
        + "const normalize=(v)=>String(v||'').replace(/\\s+/g,' ').trim();"
        + "const visible=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const candidates=(selectors)=>selectors.flatMap((selector)=>Array.from(document.querySelectorAll(selector))).filter(visible);"
        + "return {href:location.href,title:document.title,text:normalize(document.body?document.body.innerText:''),"
        + "inputs:candidates(['input']).map((input)=>({type:input.type||'',name:input.name||'',id:input.id||'',"
        + "autocomplete:input.autocomplete||'',placeholder:input.placeholder||'',maxLength:input.maxLength||0})).slice(0,30),"
        + "actions:candidates(['button','input[type=\"submit\"]','a','[role=\"button\"]','label']).map((el)=>"
        + "normalize(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent)).filter(Boolean).slice(0,60),"
        + "links:Array.from(document.querySelectorAll('a')).map((a)=>a.href||'').filter(Boolean).slice(0,80)};"
        + "})()";
  }

  private String visibleHelpers() {
    return "const normalize=(v)=>String(v||'').replace(/\\s+/g,' ').trim();"
        + "const visible=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const candidates=(selectors)=>selectors.flatMap((selector)=>Array.from(document.querySelectorAll(selector))).filter(visible);"
        + "const setValue=(el,value)=>{el.focus();const d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');"
        + "if(d&&d.set){d.set.call(el,value);}else{el.value=value;}"
        + "el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};";
  }

  private boolean matches(String text, String regex) {
    return Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(text == null ? "" : text).find();
  }

  private boolean isAccountLocked(String text) {
    return matches(text, "account is locked|locked your account|account locked");
  }

  private boolean isCookieNotice(String text) {
    return matches(text,
        "cookiebot|this website uses cookies|about this website uses cookies|consent details|manage cookies"
            + "|use necessary cookies only|allow all cookies|cookies to personalise");
  }

  private boolean isInvalidCredentials(String text) {
    return matches(text,
        "email address or password.{0,140}incorrect"
            + "|incorrect.{0,80}(email address|password|credentials)"
            + "|invalid credentials"
            + "|invalid login"
            + "|unable to log you in"
            + "|problem occurred when trying to log you in"
            + "|trying to log into a runescape account.{0,160}upgrad");
  }

  private boolean isRejectedVerificationCode(String text) {
    return matches(text,
        "(incorrect|invalid|expired|wrong).{0,100}(verification|authenticator|security|two[- ]?factor|totp)?\\s*code"
            + "|code.{0,100}(incorrect|invalid|expired|wrong)"
            + "|authenticator.{0,100}(incorrect|invalid|expired|wrong)");
  }

  private boolean looksLikeOAuthCallback(String url) {
    String text = String.valueOf(url == null ? "" : url).toLowerCase(Locale.ROOT);
    return text.contains("code=") || text.contains("id_token=");
  }

  private String brief(String text) {
    String clean = String.valueOf(text == null ? "" : text).replaceAll("\\s+", " ").trim();
    return clean.length() <= 240 ? clean : clean.substring(0, 240);
  }

  private void sleep(long millis) {
    control.sleep(millis);
  }

  static final class TemporaryOAuthException extends Exception {
    TemporaryOAuthException(String message) {
      super(message);
    }
  }

  static final class TerminalAuthException extends Exception {
    private final String status;

    TerminalAuthException(String status, String message) {
      super(message);
      this.status = status;
    }

    String status() {
      return status;
    }
  }

  private static final class State {
    final String href;
    final String title;
    final String text;
    final List<Map<String, Object>> inputs;
    final List<String> actions;
    final List<String> links;

    State(String href, String title, String text, List<Map<String, Object>> inputs,
        List<String> actions, List<String> links) {
      this.href = href;
      this.title = title;
      this.text = text;
      this.inputs = inputs;
      this.actions = actions;
      this.links = links;
    }

    static State from(Map<String, Object> raw) {
      ArrayList<Map<String, Object>> inputs = new ArrayList<>();
      for (Object input : Json.asList(raw.get("inputs"))) {
        inputs.add(Json.asObject(input));
      }
      ArrayList<String> actions = new ArrayList<>();
      for (Object action : Json.asList(raw.get("actions"))) {
        actions.add(Json.string(action));
      }
      ArrayList<String> links = new ArrayList<>();
      for (Object link : Json.asList(raw.get("links"))) {
        links.add(Json.string(link));
      }
      return new State(
          Json.string(raw.get("href")),
          Json.string(raw.get("title")),
          Json.string(raw.get("text")),
          inputs,
          actions,
          links);
    }
  }
}
