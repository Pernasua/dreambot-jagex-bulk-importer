package com.pernasua.dreambot.jageximporter;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Pattern;

final class JagexCdpAutomation {
  private static final List<String> BLOCKED_URL_PATTERNS = blockedUrlPatterns();
  private final BrowserSession browser;
  private final long humanCheckWaitMs;
  private final Consumer<String> log;
  private final RunControl control;
  private String importMailCodeHelper = "";
  private final String screenshotDir = System.getenv().getOrDefault("DREAMBOT_JAGEX_IMPORTER_SHOT_DIR",
      "/tmp/enroll-shots");

  // When set, completeAuth logs in via the EMAIL 2FA code (read with this helper) instead of the
  // authenticator code — the login-time authenticator prompt is an unreachable modal.
  void setImportMailCodeHelper(String helper) {
    this.importMailCodeHelper = helper == null ? "" : helper;
  }

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

  private static List<String> blockedUrlPatterns() {
    String raw = String.valueOf(System.getenv("DREAMBOT_JAGEX_IMPORTER_BLOCK_URL_PATTERNS") == null
        ? ""
        : System.getenv("DREAMBOT_JAGEX_IMPORTER_BLOCK_URL_PATTERNS")).trim();
    if (raw.isEmpty()) {
      return java.util.List.of();
    }
    ArrayList<String> out = new ArrayList<>();
    for (String part : raw.split(",")) {
      String pattern = part.trim();
      if (!pattern.isEmpty()) {
        out.add(pattern);
      }
    }
    return out;
  }

  JagexOAuthClient.Callback completeAuth(JagexOAuthClient.AuthRequest request, String email,
      String password, String otpSecret) throws Exception {
    control.checkpoint();
    browser.prepareAuthRequest(request);
    boolean nativeJcefNavigation = browser.engine == BrowserEngine.JCEF;
    boolean launcherFlow = request.url.contains("flow=launcher");
    boolean directOpenNavigation = !nativeJcefNavigation && request.url.contains("prompt=consent");
    if (nativeJcefNavigation) {
      browser.navigate(request.url);
      sleep(6_000);
    }
    CdpClient cdp = directOpenNavigation ? openPage(request.url) : openPage();
    try {
      if (!request.referrer.isEmpty()) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        headers.put("Referer", request.referrer);
        cdp.setExtraHttpHeaders(headers);
      }
      if (!nativeJcefNavigation && launcherFlow) {
        log.accept("probing Jagex reachability before launcher OAuth");
        try {
          cdp = waitForJagexReachability(cdp, "https://account.jagex.com/", 10_000L);
        } catch (TemporaryOAuthException exception) {
          // This probe is just a warm-up. If it flakes, the real manage/profile
          // navigation below is the authoritative signal, so don't burn an entire
          // fresh-browser retry on the probe alone.
          log.accept("Jagex reachability probe failed but will continue to warm profile directly: "
              + brief(exception.getMessage()));
          cdp = reopenPageTarget(cdp, "https://account.jagex.com/");
        }
        log.accept("warming Jagex profile session before launcher OAuth");
        navigateForOAuth(cdp, "https://account.jagex.com/en-GB/manage/profile",
            "warm Jagex profile before launcher OAuth");
        sleep(1_500);
        State warmState = readStateWithReopen(cdp,
            "https://account.jagex.com/en-GB/manage/profile",
            "warm Jagex profile before launcher OAuth");
        if (humanChallengePresent(cdp, warmState)) {
          log.accept("warm profile hit a human-check page before launcher OAuth");
          if (!waitPastHumanCheck(cdp, "")) {
            throw new IllegalStateException("human check did not clear while warming Jagex profile");
          }
        }
      }
      if (!nativeJcefNavigation && !directOpenNavigation) {
        navigateForOAuth(cdp, request.url,
            request.url.contains("flow=launcher") ? "launcher OAuth entry"
                : "Jagex account consent OAuth");
      }
      sleep(800);
      long totalWaitMs = Math.max(420_000L, humanCheckWaitMs + 180_000L);
      long deadline = System.currentTimeMillis() + totalWaitMs;
      boolean emailFilled = false;
      boolean passwordFilled = false;
      int passwordResubmitAttempts = 0;
      long lastCodeCounter = -1L;
      long lastCodeSubmitAt = 0L;
      int codeSubmitAttempts = 0;
      int codeRejections = 0;
      int methodSwitchAttempts = 0;
      boolean forceEmailFallback = false;
      long importMailCodeAfter = System.currentTimeMillis() / 1000L - 30L;
      String importLastEmailCode = "";
      long importLastEmailCodeAt = 0L;
      int importEmailCodeAttempts = 0;
      int importLoop = 0;
      boolean humanLogged = false;
      boolean authPageLogged = false;
      String lastAction = "";
      long lastActionAt = System.currentTimeMillis();
      String lastStateFingerprint = "";
      long sameStateSince = 0L;
      int reopenAttempts = 0;
      int blankConsentReloads = 0;
      int browserErrorReopens = 0;

      while (System.currentTimeMillis() < deadline) {
        control.checkpoint();
        State state;
        try {
          state = readState(cdp);
        } catch (RuntimeException exception) {
          if (!isCdpTimeout(exception) || reopenAttempts >= 4) {
            throw exception;
          }
          reopenAttempts++;
          throw new TemporaryOAuthException("readState timed out during OAuth after " + lastAction
              + "; retrying with a fresh browser (" + reopenAttempts + "/4)");
        }
        long now = System.currentTimeMillis();
        String stateFingerprint = stateFingerprint(state);
        if (stateFingerprint.equals(lastStateFingerprint)) {
          if (sameStateSince == 0L) {
            sameStateSince = now;
          }
        } else {
          lastStateFingerprint = stateFingerprint;
          sameStateSince = now;
        }
        JagexOAuthClient.Callback callback = callback(state, cdp.observedUrls(), request.state);
        if (callback != null) {
          return finishAuth(cdp, callback);
        }
        if (looksLikeOAuthCallback(state.href)) {
          lastAction = "waiting for OAuth callback state";
          lastActionAt = now;
          sleep(650);
          continue;
        }

        String text = state.text.toLowerCase(Locale.ROOT);
        if (++importLoop % 8 == 1) {
          log.accept("oauth [" + (lastAction.isEmpty() ? "navigating" : lastAction) + "] @ "
              + brief(state.href) + " :: " + brief(state.text));
          if (importLoop < 240) {
            screenshot(cdp, "import-L" + String.format(Locale.ROOT, "%03d", importLoop));
          }
        }
        if (state.href.startsWith("chrome-error://")
            || matches(text, "err_blocked_by_client|this page has been blocked by (chrome|chromium)"
                + "|site can.t be reached|err_[a-z_]+")) {
          if (!nativeJcefNavigation && launcherFlow && browserErrorReopens < 2) {
            browserErrorReopens++;
            log.accept("launcher OAuth hit browser error page; reopening page target directly "
                + browserErrorReopens + "/2");
            cdp = reopenPageTarget(cdp, request.url);
            lastAction = "reopened launcher page after browser error";
            lastActionAt = now;
            lastStateFingerprint = "";
            sameStateSince = 0L;
            sleep(1_500);
            continue;
          }
          throw new TemporaryOAuthException("browser error page during Jagex OAuth: "
              + brief(state.href + " " + state.text));
        }
        if (state.href.contains("error=") || matches(text, "invalid_request|oauth.*error|redirect_uri")) {
          throw new IllegalStateException("Jagex OAuth error page: " + brief(state.text));
        }
        String cookieClick = dismissCookieNotice(cdp, text);
        if (!cookieClick.isEmpty()) {
          lastAction = "dismissed cookie notice";
          lastActionAt = now;
          sleep(600);
          continue;
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

        cookieClick = dismissCookieNotice(cdp, text);
        if (!cookieClick.isEmpty()) {
          lastAction = "dismissed cookie notice";
          lastActionAt = now;
          sleep(600);
          continue;
        }

        if (humanChallengePresent(cdp, state)) {
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
          if (clickText(cdp, Arrays.asList("^continue$", "^next$", "^submit$", "^verify$")).isEmpty()) {
            pressEnter(cdp);
          }
          emailFilled = true;
          lastAction = "submitted email";
          lastActionAt = now;
          sleep(800);
          continue;
        }

        if (hasInput(state, "password") && !passwordFilled) {
          fillFirst(cdp, Arrays.asList(
              "input[type='password']",
              "input[name='password']",
              "input[id*='password' i]",
              "input[autocomplete='current-password']"), password);
          if (clickText(cdp, Arrays.asList("^continue$", "^next$", "^submit$", "^verify$")).isEmpty()) {
            pressEnter(cdp);
          }
          passwordFilled = true;
          lastAction = "submitted password";
          lastActionAt = now;
          sleep(1_000);
          continue;
        }

        if ("submitted password".equals(lastAction)
            && passwordFilled
            && passwordResubmitAttempts < 1
            && hasInput(state, "password")
            && matches(text, "log into your jagex account|enter your password to continue")
            && !passwordSubmitLooksRejected(text)
            && now - lastActionAt >= 3_000L) {
          passwordResubmitAttempts++;
          log.accept("password form is still present after submit; re-submitting "
              + passwordResubmitAttempts + "/1");
          fillFirst(cdp, Arrays.asList(
              "input[type='password']",
              "input[name='password']",
              "input[id*='password' i]",
              "input[autocomplete='current-password']"), password);
          if (clickText(cdp, Arrays.asList("^continue$", "^next$", "^submit$", "^verify$", "^log in$", "^sign in$")).isEmpty()) {
            pressEnter(cdp);
          }
          lastAction = "resubmitted password";
          lastActionAt = now;
          sleep(1_200);
          continue;
        }

        String wide = (text + " " + deepInnerText(cdp)).toLowerCase(Locale.ROOT);

        boolean preferAuthenticator = otpSecret != null && !otpSecret.isBlank() && !forceEmailFallback;

        // A "choose how to verify" page (the account may have both email and authenticator 2FA):
        // when we already have a validated authenticator secret, prefer that path first. The
        // factory disables email 2FA best-effort, but if Jagex still offers both methods during
        // import we want the more deterministic authenticator route, not the mailbox fallback.
        if (preferAuthenticator
            && !codeInputReady(state)
            && !isAuthenticatorCodePage(wide)
            && matches(wide, "send a code to your email address|choose.*verification|verify another way|two-step|two factor")
            && matches(wide, "authenticator")) {
          String clicked = clickText(cdp, Arrays.asList("use your authenticator app", "authenticator app", "authenticator"));
          if (!clicked.isEmpty()) {
            lastAction = "selected authenticator";
            lastActionAt = now;
            sleep(900);
            continue;
          }
        }

        // 2FA method-selection ("Choose a way to verify it's you"): when we can read email codes,
        // pick EMAIL — the authenticator-code prompt is an unreachable modal.
        if ((forceEmailFallback || !preferAuthenticator)
            && !importMailCodeHelper.isEmpty()
            && !matches(text, "enter (?:the )?(?:verification|security) code|code sent to")
            && (matches(wide, "choose a way to verify|verify it.?s you")
                || (matches(wide, "use your authenticator app") && matches(wide, "send a code to your email")))) {
          String pick = clickText(cdp, Arrays.asList(
              "send a code to your email", "code to your email address", "to your email address"));
          if (pick.isEmpty()) {
            pick = clickExactButton(cdp, "^(send a code to your email address|use your email address|email address)$");
          }
          if (!pick.isEmpty()) {
            importMailCodeAfter = System.currentTimeMillis() / 1000L - 5L;
            lastAction = "selected email 2FA method (import)";
            lastActionAt = now;
            sleep(1_300);
            continue;
          }
        }

        // Jagex's email-code wording ("...code sent to <address>") doesn't match isEmailCodePage, so
        // also key off the URL and that copy (same broadening as enrollAuthenticator).
        boolean emailCodePage = !matches(text, "authenticator")
            && (matches(state.href, "email-code-verify") || isEmailCodePage(text)
                || matches(text, "emailed you a verification code|enter the code sent to|code sent to [^ ]+@"));
        boolean onCodePage = codeInputReady(state) || isAuthenticatorCodePage(text) || emailCodePage;
        if (!onCodePage && isAuthenticatorCodePage(deepInnerText(cdp))) {
          onCodePage = true;  // the authenticator-code prompt is a shadow-DOM modal
        }
        if (onCodePage) {
          if (emailCodePage && preferAuthenticator) {
            if (methodSwitchAttempts >= 3) {
              throw new TerminalAuthException("email_2fa_required",
                  "Jagex is still prompting for an email security code even though an authenticator"
                      + " secret is available, and the authenticator option could not be reached.");
            }
            methodSwitchAttempts++;
            String switched = clickText(cdp, Arrays.asList(
                "verify another way", "try another way", "use a different method",
                "choose another method", "more options"));
            if (switched.isEmpty()) {
              switched = clickText(cdp, Arrays.asList(
                  "use your authenticator app", "authenticator app", "authenticator"));
            }
            if (!switched.isEmpty()) {
              lastAction = "switching from email prompt to authenticator (" + switched + ")";
              lastActionAt = now;
              log.accept("Jagex showed an email-code prompt; switching to the authenticator method ("
                  + switched + ")");
              sleep(900);
              continue;
            }
          }
          if (emailCodePage && !isAuthenticatorCodePage(text)) {
            if (!importMailCodeHelper.isEmpty()) {
              // Log in via the EMAIL code (reachable) rather than the authenticator-code modal
              // (unreachable). The TOTP secret is still stored in the DreamBot DB for in-game use.
              if (importEmailCodeAttempts >= 5) {
                throw new TerminalAuthException("email_2fa_required",
                    "Jagex kept rejecting the emailed login code during import");
              }
              String mailCode = fetchEmailCode(email, importMailCodeHelper, importMailCodeAfter,
                  importLastEmailCode);
              if (mailCode.isEmpty()) {
                throw new TerminalAuthException("email_2fa_required",
                    "no Jagex email login code arrived during import");
              }
              if (mailCode.equalsIgnoreCase(importLastEmailCode) && !isRejectedVerificationCode(text)
                  && System.currentTimeMillis() - importLastEmailCodeAt < 8_000L) {
                sleep(1_000);
                continue;
              }
              boolean filledEmail = false;
              for (int t = 0; t < 5 && !filledEmail; t++) {
                filledEmail = fillCodeDeep(cdp, mailCode);
                if (!filledEmail) {
                  sleep(1_200);
                }
              }
              if (!filledEmail) {
                sleep(800);
                continue;
              }
              importLastEmailCode = mailCode;
              importLastEmailCodeAt = System.currentTimeMillis();
              importEmailCodeAttempts++;
              lastAction = "submitted email login code (import)";
              lastActionAt = now;
              sleep(1_800);
              continue;
            }
            // Jagex is asking for an email security code (the account also has email 2FA). Try to
            // switch to the authenticator method instead of submitting a TOTP that will be rejected.
            if (methodSwitchAttempts >= 3) {
              throw new TerminalAuthException("email_2fa_required",
                  "Jagex is prompting for an email security code and the authenticator option could not"
                      + " be reached; this account has email-based 2FA. Disable email 2FA so the"
                      + " authenticator is the only login method, then re-import.");
            }
            methodSwitchAttempts++;
            String switched = clickText(cdp, Arrays.asList(
                "verify another way", "try another way", "use a different method",
                "choose another method", "more options"));
            if (switched.isEmpty()) {
              switched = clickText(cdp, Arrays.asList(
                  "use your authenticator app", "authenticator app", "authenticator"));
            }
            if (!switched.isEmpty()) {
              lastAction = "switching from email prompt to authenticator (" + switched + ")";
              lastActionAt = now;
              log.accept("Jagex showed an email-code prompt; switching to the authenticator method ("
                  + switched + ")");
              sleep(900);
              continue;
            }
            throw new TerminalAuthException("email_2fa_required",
                "Jagex is prompting for an email security code and no control to switch to the"
                    + " authenticator was found; this account has email-based 2FA.");
          }
          if (!authPageLogged) {
            log.accept("on Jagex authenticator code page; entering TOTP");
            authPageLogged = true;
          }
          boolean rejected = isRejectedVerificationCode(text);
          if (rejected) {
            codeRejections++;
            if (codeRejections >= 2) {
              // Code generation matches the RFC 6238 test vectors and the host clock is sound, so a
              // code rejected in two separate 30s windows means the secret itself does not match.
              throw new TerminalAuthException("invalid_otp_code",
                  "Jagex rejected the authenticator code in two separate time windows. The generated"
                      + " codes are valid TOTP (verified against the RFC test vectors) and the system"
                      + " clock is correct, so the stored TOTP secret is wrong for this account.");
            }
          }
          if (!rejected && codeSubmitAttempts >= 2 && !importMailCodeHelper.isEmpty()) {
            forceEmailFallback = true;
            String switched = clickText(cdp, Arrays.asList(
                "verify another way", "try another way", "use a different method",
                "choose another method", "more options"));
            if (!switched.isEmpty()) {
              lastAction = "switching from stalled authenticator prompt to email (" + switched + ")";
              lastActionAt = now;
              log.accept("authenticator prompt accepted the digits but did not advance; switching to"
                  + " the email-code method (" + switched + ")");
              sleep(900);
              continue;
            }
          }
          Totp.Code pending = Totp.generate(otpSecret);
          boolean firstSubmit = lastCodeSubmitAt == 0L;
          boolean newWindow = pending.counter != lastCodeCounter;
          boolean settling = !firstSubmit && System.currentTimeMillis() - lastCodeSubmitAt < 3_500L;
          if (!firstSubmit && !rejected && (!newWindow || settling)) {
            // Already submitted this window's code; give the page time to react before resubmitting.
            sleep(650);
            continue;
          }
          if (codeSubmitAttempts >= 4) {
            throw new IllegalStateException("Jagex stayed on the authenticator-code page after "
                + codeSubmitAttempts + " submissions; the digits were typed and read back from the field"
                + " correctly but the page neither advanced nor reported the code as wrong");
          }
          Totp.Code code = freshTotp(otpSecret);
          if (rejected && code.counter == lastCodeCounter) {
            // Never resubmit the exact code Jagex just rejected; wait for the next window.
            sleep((code.remainingSeconds + 1L) * 1000L);
            code = freshTotp(otpSecret);
          }
          if (!fillCodeDeep(cdp, code.value)) {
            throw new IllegalStateException("could not enter the authenticator code into the Jagex code"
                + " field; the input did not accept the typed digits");
          }
          lastCodeCounter = code.counter;
          lastCodeSubmitAt = System.currentTimeMillis();
          codeSubmitAttempts++;
          lastAction = "submitted authenticator code";
          lastActionAt = now;
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
            lastActionAt = now;
            sleep(900);
            continue;
          }
        }

        if (isConsentChallengePage(state.href) && isBlankSpinnerState(state)) {
          long sameStateFor = sameStateSince <= 0L ? 0L : now - sameStateSince;
          if (sameStateFor >= 20_000L && blankConsentReloads < 2) {
            blankConsentReloads++;
            log.accept("consent OAuth page is still a blank spinner after "
                + (sameStateFor / 1000L) + "s; reloading consent challenge "
                + blankConsentReloads + "/2");
            navigateForOAuth(cdp, state.href, "blank consent challenge reload");
            lastAction = "reloaded blank consent challenge";
            lastActionAt = now;
            lastStateFingerprint = "";
            sameStateSince = 0L;
            sleep(1_500);
            continue;
          }
        }

        if (oauthSpinnerStalled(state, text, lastAction, lastActionAt, sameStateSince, now)) {
          throw new TemporaryOAuthException("Jagex OAuth spinner/page stall after " + lastAction
              + " @ " + brief(state.href + " " + state.text));
        }

        if (lastAction.isEmpty() && state.actions.isEmpty() && state.text.isEmpty()) {
          lastAction = "waiting for page";
          lastActionAt = now;
        }
        sleep(650);
      }
      throw new TemporaryOAuthException("timed out waiting for Jagex OAuth callback after " + lastAction);
    } finally {
      cdp.close();
    }
  }

  /**
   * Enroll a fresh TOTP authenticator on an account that has none yet and return its
   * base32 secret. Mirrors the Playwright signup helper's setupAuthenticator flow, but
   * runs in this JCEF/CDP browser, which clears the MFA-endpoint Cloudflare that the
   * Playwright browser cannot. Used when an import row provides an empty otp-secret.
   */
  String enrollAuthenticator(String email, String password, String mailCodeHelper) throws Exception {
    String securityUrl = "https://account.jagex.com/en-GB/manage";
    // Mirror completeAuth: native JCEF navigation passes Cloudflare where a CDP-issued
    // navigation does not (CDP-driven loads are more detectable to the challenge).
    boolean nativeJcefNavigation = browser.engine == BrowserEngine.JCEF;
    if (nativeJcefNavigation) {
      browser.navigate(securityUrl);
      sleep(6_000);
    }
    CdpClient cdp = openPage(securityUrl);
    try {
      if (!nativeJcefNavigation) {
        sleep(800);
      }
      long deadline = System.currentTimeMillis() + Math.max(420_000L, humanCheckWaitMs + 180_000L);
      boolean emailFilled = false;
      boolean passwordFilled = false;
      boolean submittedCode = false;
      String secret = "";
      long lastCodeCounter = -1L;
      long lastCodeSubmitAt = 0L;
      int codeAttempts = 0;
      int loopCount = 0;
      int shotCount = 0;
      int reopenAttempts = 0;
      long mailCodeAfter = 0L;
      String lastEmailCode = "";
      long lastEmailCodeAt = 0L;
      int emailCodeAttempts = 0;
      String lastDumpHref = "";
      String lastAction = "navigating";

      while (System.currentTimeMillis() < deadline) {
        State state;
        try {
          state = readState(cdp);
        } catch (RuntimeException exception) {
          if (!isCdpTimeout(exception) || reopenAttempts >= 4) {
            throw exception;
          }
          reopenAttempts++;
          log.accept("readState timed out during enroll; reopening fresh page target in the same session (attempt "
              + reopenAttempts + ")");
          cdp = reopenPageTarget(cdp, securityUrl);
          lastAction = "reopened page after runtime timeout";
          continue;
        }
        String text = state.text.toLowerCase(Locale.ROOT);
        if (++loopCount % 8 == 1) {
          log.accept("enroll [" + lastAction + "] @ " + brief(state.href) + " :: " + brief(state.text));
          if (shotCount < 30) {
            screenshot(cdp, "L" + String.format(Locale.ROOT, "%03d", loopCount));
            shotCount++;
          }
        }

        if (humanChallengePresent(cdp, state)) {
          if (browser.engine == BrowserEngine.JCEF) {
            browser.reveal();
          }
          if (!waitPastHumanCheck(cdp, "")) {
            throw new IllegalStateException("human check did not clear within " + humanCheckWaitMs
                + "ms during authenticator enrollment");
          }
          continue;
        }
        if (!dismissCookieNotice(cdp, text).isEmpty()) {
          sleep(600);
          continue;
        }
        if (matches(text, "too many requests|tried to do that too many times|rate limit")) {
          throw new IllegalStateException("Jagex rate limited authenticator enrollment: " + brief(state.text));
        }
        if (matches(text, "technical difficulties|try again later|temporarily unavailable|service unavailable"
            + "|something went wrong")) {
          throw new IllegalStateException("Jagex temporary page during authenticator enrollment: "
              + brief(state.text));
        }
        if (isAccountLocked(text)) {
          throw new IllegalStateException("Jagex reported the account is locked");
        }
        if (isInvalidCredentials(text)) {
          throw new IllegalStateException("Jagex login failed during enrollment (invalid credentials): "
              + brief(state.text));
        }

        if (hasInput(state, "email") && !emailFilled) {
          fillFirst(cdp, Arrays.asList("input[type='email']", "input[name='email']",
              "input[id*='email' i]", "input[autocomplete='email']", "input"), email);
          if (clickText(cdp, Arrays.asList("^continue$", "^next$", "^submit$", "^verify$")).isEmpty()) {
            pressEnter(cdp);
          }
          emailFilled = true;
          lastAction = "submitted email";
          sleep(900);
          continue;
        }
        if (hasInput(state, "password") && !passwordFilled) {
          fillFirst(cdp, Arrays.asList("input[type='password']", "input[name='password']",
              "input[id*='password' i]", "input[autocomplete='current-password']"), password);
          if (clickText(cdp, Arrays.asList("^continue$", "^next$", "^submit$", "^verify$")).isEmpty()) {
            pressEnter(cdp);
          }
          passwordFilled = true;
          mailCodeAfter = System.currentTimeMillis() / 1000L - 5L;
          lastAction = "submitted password";
          sleep(1_100);
          continue;
        }

        // Fresh-device login on an account without an authenticator triggers an emailed login
        // code. Read it from the mailbox (the factory's 2b2m Maildir helper) and submit it.
        // Jagex's wording ("We've emailed you a verification code ... sent to <address>") does not
        // match isEmailCodePage's patterns, so key off the URL and the actual copy as well.
        boolean emailLoginCodePage = !isAuthenticatorCodePage(text) && !matches(text, "authenticator")
            && (matches(state.href, "email-code-verify")
                || isEmailCodePage(text)
                || matches(text, "emailed you a verification code|enter the code sent to|code sent to [^ ]+@"));
        if (emailLoginCodePage) {
          if (mailCodeHelper == null || mailCodeHelper.isEmpty()) {
            throw new IllegalStateException("Jagex requires an email login code but no mail-code helper"
                + " is configured (pass --mail-code-helper)");
          }
          if (emailCodeAttempts >= 4) {
            throw new IllegalStateException("Jagex kept rejecting the emailed login code");
          }
          if (mailCodeAfter == 0L) {
            mailCodeAfter = System.currentTimeMillis() / 1000L - 120L;
          }
          String code = fetchEmailCode(email, mailCodeHelper, mailCodeAfter, lastEmailCode);
          if (code.isEmpty()) {
            throw new IllegalStateException("no Jagex email login code arrived in the mailbox");
          }
          if (code.equalsIgnoreCase(lastEmailCode) && !isRejectedVerificationCode(text)
              && System.currentTimeMillis() - lastEmailCodeAt < 8_000L) {
            sleep(1_000);
            continue;
          }
          boolean filled = false;
          for (int fillTry = 0; fillTry < 5 && !filled; fillTry++) {
            filled = fillCodeDeep(cdp, code);
            if (!filled) {
              sleep(1_200);  // the shadow-DOM code input can render a beat after the page text
            }
          }
          if (!filled) {
            log.accept("email-code input not found even after piercing shadow DOM");
            sleep(800);
            continue;
          }
          lastEmailCode = code;
          lastEmailCodeAt = System.currentTimeMillis();
          emailCodeAttempts++;
          lastAction = "submitted email login code";
          sleep(1_800);
          continue;
        }

        if (submittedCode && !secret.isEmpty()
            && matches(text, "backup codes|recovery codes|authenticator.*enabled|enabled.*authenticator|"
                + "successfully|you'?re all set|two-step.*on")) {
          clickText(cdp, Arrays.asList("^continue$", "^done$", "^finish$", "i have saved",
              "i'?ve saved", "i have copied", "^close$", "^ok$"));
          log.accept("authenticator enrolled");
          return secret;
        }

        if (state.href.contains("/manage/oauth2/code")) {
          if (browser.engine == BrowserEngine.JCEF) {
            browser.navigate("https://account.jagex.com/en-GB/manage/profile");
          } else {
            cdp.navigate("https://account.jagex.com/en-GB/manage/profile");
          }
          lastAction = "followed manage oauth callback";
          sleep(1500);
          continue;
        }

        if (secret.isEmpty()) {
          String enrollText = readEnrollmentText(cdp);
          // Only parse the secret on the actual authenticator setup page (QR / manual key). Keying off
          // page CONTENT — not a "clicked Enable" flag — avoids false-matching the account page (whose
          // CSS/tokens can look base32-ish) and survives the re-auth detour Jagex inserts after Enable.
          boolean onSetupPage = matches(text,
              "scan|qr code|setup key|secret key|enter this key|enter the key|use this key|manual key");
          if (onSetupPage) {
            if (!state.href.equals(lastDumpHref)) {
              lastDumpHref = state.href;
              log.accept("ENROLL-SETUP-DUMP @ " + brief(state.href) + " <<<"
                  + (enrollText.length() > 2200 ? enrollText.substring(0, 2200) : enrollText) + ">>>");
            }
            secret = extractSecretFromText(enrollText);
            if (!secret.isEmpty()) {
              log.accept("extracted authenticator secret (len " + secret.length() + ") @ " + brief(state.href));
              sleep(400);
              continue;
            }
          }
          // 1. Reveal the manual setup key if on the QR page.
          String reveal = clickText(cdp, Arrays.asList(
              "can.?t scan", "cannot scan", "unable to scan", "enter.*key manually",
              "enter.*manually", "manual.*key", "setup key", "secret key", "show.*key", "enter.*key"));
          if (!reveal.isEmpty()) {
            lastAction = "clicked " + reveal;
            sleep(1_000);
            continue;
          }
          // Some account-verification modals ("Verify your account" -> "Start") sit over the account
          // page but don't reliably surface their text through the current page-state scrape. Prefer a
          // small exact-button advance before re-clicking the underlying Enable control.
          String begin = clickExactButton(cdp, "^(start|continue|next|confirm)$");
          if (!begin.isEmpty()) {
            lastAction = "clicked " + begin;
            sleep(1_200);
            continue;
          }
          // 2. Otherwise start authenticator setup from the account page ("Enable").
          String started = clickExactButton(cdp,
              "^(enable|set up|set up authenticator|add authenticator|get started)$");
          if (started.isEmpty()) {
            started = clickExactButton(cdp, "^(continue|next|confirm|set up authenticator app)$");
          }
          if (!started.isEmpty()) {
            lastAction = "clicked " + started;
            sleep(1_200);
            continue;
          }
          sleep(700);
          continue;
        }

        // The setup modal's QR / manual-key step is showing (we already hold the secret). Click
        // Continue to reach the code-entry step that actually confirms the authenticator — do this
        // BEFORE the code-confirm branch, which otherwise mis-fires here (it sees "authenticator"
        // text + an input) and loops typing codes with nowhere to submit them.
        if (!secret.isEmpty() && !submittedCode
            && matches(text, "set up your authenticator app|scan the qr|scan this qr"
                + "|enter this code manually|download an authenticator")) {
          String adv = clickExactButton(cdp, "^(continue|next)$");
          if (!adv.isEmpty()) {
            lastAction = "advanced past QR step (" + adv + ")";
            sleep(1_500);
            continue;
          }
        }

        if (isAuthenticatorCodePage(text) || codeInputReady(state)) {
          boolean rejected = isRejectedVerificationCode(text);
          if (codeAttempts >= 6) {
            throw new IllegalStateException("Jagex repeatedly rejected the authenticator setup code");
          }
          Totp.Code code = freshTotp(secret);
          if (lastCodeSubmitAt > 0L && !rejected && code.counter == lastCodeCounter
              && System.currentTimeMillis() - lastCodeSubmitAt < 4_000L) {
            sleep(650);
            continue;
          }
          if (rejected && code.counter == lastCodeCounter) {
            sleep((code.remainingSeconds + 1L) * 1000L);
            code = freshTotp(secret);
          }
          if (!fillCodeDeep(cdp, code.value)) {
            sleep(700);
            continue;
          }
          lastCodeCounter = code.counter;
          lastCodeSubmitAt = System.currentTimeMillis();
          codeAttempts++;
          submittedCode = true;
          lastAction = "submitted setup code";
          sleep(1_300);
          continue;
        }

        clickText(cdp, Arrays.asList("^continue$", "^next$", "^start$", "^done$"));
        sleep(700);
      }
      if (!secret.isEmpty() && submittedCode) {
        return secret;
      }
      throw new IllegalStateException("timed out enrolling authenticator after " + lastAction);
    } finally {
      cdp.close();
    }
  }

  private boolean isCdpTimeout(RuntimeException exception) {
    return exception != null
        && String.valueOf(exception.getMessage()).toLowerCase(Locale.ROOT).contains("timed out");
  }

  private boolean isClosedCdpTransport(RuntimeException exception) {
    if (exception == null) {
      return false;
    }
    String message = String.valueOf(exception.getMessage()).toLowerCase(Locale.ROOT);
    Throwable cause = exception.getCause();
    String causeMessage = cause == null ? "" : String.valueOf(cause.getMessage()).toLowerCase(Locale.ROOT);
    return message.contains("output closed")
        || message.contains("websocket closed")
        || causeMessage.contains("output closed")
        || causeMessage.contains("websocket closed");
  }

  private void navigateForOAuth(CdpClient cdp, String url, String action) throws Exception {
    try {
      cdp.navigate(url);
    } catch (RuntimeException exception) {
      if (isCdpTimeout(exception) || isClosedCdpTransport(exception)) {
        throw new TemporaryOAuthException(action + " navigation timeout @ " + brief(url));
      }
      throw exception;
    }
  }

  private CdpClient reopenPageTarget(CdpClient current, String url) throws Exception {
    try {
      current.close();
    } catch (Exception ignored) {
      // Best-effort cleanup only; the replacement target is what matters.
    }
    CdpClient fresh = browser.engine == BrowserEngine.JCEF ? openPage() : openPage(url);
    if (browser.engine == BrowserEngine.JCEF) {
      fresh.navigate(url);
      sleep(1_500);
    } else {
      sleep(1_200);
    }
    return fresh;
  }

  private CdpClient waitForJagexReachability(CdpClient cdp, String url, long maxWaitMs)
      throws Exception {
    long deadline = System.currentTimeMillis() + Math.max(0L, maxWaitMs);
    int attempt = 0;
    while (System.currentTimeMillis() < deadline) {
      attempt++;
      try {
        navigateForOAuth(cdp, url, "Jagex reachability probe");
      } catch (TemporaryOAuthException exception) {
        log.accept("Jagex reachability probe navigation timed out; reopening page target "
            + attempt + " :: " + brief(exception.getMessage()));
        cdp = reopenPageTarget(cdp, url);
        sleep(1_200);
        continue;
      }
      sleep(900);
      State state = readStateWithReopen(cdp, url, "Jagex reachability probe");
      String text = state.text.toLowerCase(Locale.ROOT);
      if (!(state.href.startsWith("chrome-error://")
          || matches(text, "err_blocked_by_client|this page has been blocked by (chrome|chromium)"
              + "|site can.t be reached|err_[a-z_]+"))) {
        return cdp;
      }
      log.accept("Jagex reachability probe hit browser error page; reopening page target "
          + attempt);
      cdp = reopenPageTarget(cdp, url);
      sleep(1_200);
    }
    throw new TemporaryOAuthException("Jagex reachability probe timed out @ " + brief(url));
  }

  private State readStateWithReopen(CdpClient cdp, String url, String action) throws Exception {
    RuntimeException last = null;
    for (int attempt = 1; attempt <= 3; attempt++) {
      try {
        return readState(cdp);
      } catch (RuntimeException exception) {
        last = exception;
        if (!(isCdpTimeout(exception) || isClosedCdpTransport(exception)) || attempt >= 3) {
          throw exception;
        }
        log.accept(action + " readState timed out; reopening page target "
            + attempt + " :: " + brief(exception.getMessage()));
        cdp = reopenPageTarget(cdp, url);
        sleep(1_200);
      }
    }
    throw last == null ? new IllegalStateException(action + " readState failed") : last;
  }

  private String fetchEmailCode(String email, String helper, long afterEpoch, String... excludedCodes) {
    try {
      List<String> cmd = new ArrayList<>(Arrays.asList(
          "python3", helper, "--email", email, "--timeout", "180", "--interval", "3"));
      if (afterEpoch > 0L) {
        cmd.add("--after");
        cmd.add(Long.toString(afterEpoch));
      }
      if (excludedCodes != null) {
        for (String excluded : excludedCodes) {
          String value = excluded == null ? "" : excluded.trim();
          if (!value.isEmpty()) {
            cmd.add("--exclude");
            cmd.add(value);
          }
        }
      }
      log.accept("reading Jagex email login code from mailbox");
      Process proc = new ProcessBuilder(cmd).redirectErrorStream(false).start();
      String out = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
      proc.waitFor();
      String code = out.isEmpty() ? "" : out.split("\\s+")[0];
      if (!code.isEmpty()) {
        log.accept("received email login code (" + code.length() + " chars)");
      }
      return code;
    } catch (Exception exception) {
      log.accept("mail-code helper error: " + brief(exception.getMessage()));
      return "";
    }
  }

  // body.innerText plus the text inside open shadow roots — Jagex's login 2FA prompt is a shadow-DOM
  // modal whose text is absent from state.text, so the light-DOM page detectors miss it.
  private String deepInnerText(CdpClient cdp) {
    try {
      Object result = cdp.evaluate("(() => {"
          + "const parts=[document.body?document.body.innerText:''];"
          + "const seen=new Set();const visit=(root)=>{if(!root||seen.has(root))return;seen.add(root);"
          + "root.querySelectorAll&&root.querySelectorAll('*').forEach((el)=>{"
          + "if(el.shadowRoot){try{parts.push(el.shadowRoot.textContent||'');}catch(x){}visit(el.shadowRoot);}});};"
          + "visit(document);return parts.join(' ');})()");
      return result == null ? "" : result.toString();
    } catch (RuntimeException exception) {
      return "";
    }
  }

  private void screenshot(CdpClient cdp, String label) {
    try {
      LinkedHashMap<String, Object> params = new LinkedHashMap<>();
      params.put("format", "png");
      Map<String, Object> res = cdp.send("Page.captureScreenshot", params);
      Object data = res == null ? null : res.get("data");
      if (data == null) {
        return;
      }
      byte[] png = java.util.Base64.getDecoder().decode(data.toString());
      java.nio.file.Path path = java.nio.file.Paths.get(screenshotDir, label + ".png");
      java.nio.file.Files.createDirectories(path.getParent());
      java.nio.file.Files.write(path, png);
      log.accept("screenshot " + path);
    } catch (Exception exception) {
      log.accept("screenshot failed: " + brief(exception.getMessage()));
    }
  }

  private String readEnrollmentText(CdpClient cdp) {
    Object result = cdp.evaluate("(() => {"
        + "const deep=(sel)=>{const out=[];const seen=new Set();const visit=(root)=>{"
        + "if(!root||seen.has(root))return;seen.add(root);"
        + "if(root.querySelectorAll){root.querySelectorAll(sel).forEach((el)=>out.push(el));"
        + "root.querySelectorAll('*').forEach((el)=>{if(el.shadowRoot)visit(el.shadowRoot);});}};"
        + "visit(document);return out;};"
        + "const t=document.body?document.body.innerText:'';"
        + "const a=deep('a,button,input,code,span,div,img,[data-clipboard-text],[data-secret],[data-uri],[data-qr]').map((e)=>{"
        + "let s='';try{s=(e.getAttribute&&(e.getAttribute('href')||e.getAttribute('data-clipboard-text')"
        + "||e.getAttribute('data-secret')||e.getAttribute('data-uri')||e.getAttribute('data-qr')"
        + "||e.getAttribute('src')||e.getAttribute('value')||''))||'';}catch(x){}"
        + "return s+' '+(e.value||'')+' '+(e.textContent||'');}).join(' ');"
        + "return t+' '+a;})()");
    return result == null ? "" : result.toString();
  }

  private static final Pattern OTPAUTH_SECRET =
      Pattern.compile("otpauth://totp/[^\\s\"'<>]*[?&]secret=([A-Za-z2-7]{16,})", Pattern.CASE_INSENSITIVE);
  // A standalone contiguous base32 run of TOTP-key length. Prose can't match (it has spaces); hex
  // hashes can't (they contain 0/1/8/9); the OAuth code can't (it contains '_').
  private static final Pattern CONTIGUOUS_KEY = Pattern.compile("\\b([A-Za-z2-7]{26,64})\\b");
  // A label immediately followed by a contiguous base32 key (no inter-character spaces — that was
  // matching English prose).
  private static final Pattern MANUAL_KEY = Pattern.compile(
      "(?:setup key|secret key|manual key|enter this code manually|code manually|manual code|manual setup"
          + "|can.?t scan|cannot scan|enter this key|enter the key|use this key)"
          + "[^A-Za-z2-7]{0,60}([A-Za-z2-7]{16,64})", Pattern.CASE_INSENSITIVE);
  // Keys shown grouped (e.g. "abcd efgh ijkl mnop ..."). Require 6+ uniform 4-char groups so prose
  // (variable word lengths) does not match.
  private static final Pattern GROUPED_KEY =
      Pattern.compile("\\b((?:[A-Za-z2-7]{4}[\\s-]){5,15}[A-Za-z2-7]{4})\\b");

  private String extractSecretFromText(String value) {
    if (value == null || value.isEmpty()) {
      return "";
    }
    java.util.regex.Matcher matcher = OTPAUTH_SECRET.matcher(value);
    if (matcher.find()) {
      String candidate = normalizeBase32(matcher.group(1));
      if (isValidBase32Secret(candidate)) {
        return candidate;
      }
    }
    matcher = MANUAL_KEY.matcher(value);
    if (matcher.find()) {
      String candidate = normalizeBase32(matcher.group(1));
      if (isValidBase32Secret(candidate)) {
        return candidate;
      }
    }
    // Deliberately NOT falling back to any standalone/grouped base32 run here: hidden CSRF/session
    // tokens in element attributes are base32-shaped and caused false positives on the account page.
    // Only the otpauth URI or a label-anchored manual key (above) are trusted.
    return "";
  }

  private String normalizeBase32(String value) {
    return value == null ? "" : value.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
  }

  private boolean isValidBase32Secret(String value) {
    return value != null && value.length() >= 16 && value.length() <= 128 && value.matches("[A-Z2-7]+");
  }

  // Log in (email + password + emailed login code) until the account-management page is reached.
  private void loginToAccountManagement(CdpClient cdp, String email, String password, String mailCodeHelper) {
    long deadline = System.currentTimeMillis() + Math.max(420_000L, humanCheckWaitMs + 180_000L);
    boolean emailFilled = false;
    boolean passwordFilled = false;
    long mailCodeAfter = 0L;
    String lastEmailCode = "";
    long lastEmailCodeAt = 0L;
    int emailCodeAttempts = 0;
    int loop = 0;
    int shots = 0;
    while (System.currentTimeMillis() < deadline) {
      State state = readState(cdp);
      String text = state.text.toLowerCase(Locale.ROOT);
      if (++loop % 6 == 1 && shots < 18) {
        log.accept("login @ " + brief(state.href) + " :: " + brief(state.text));
        screenshot(cdp, "login-L" + String.format(Locale.ROOT, "%03d", loop));
        shots++;
      }
      if (matches(text, "two-step authentication|security codes via authenticator|language preference")
          && !matches(text, "enter (?:the )?(?:verification|security) code")
          && !hasInput(state, "password")) {
        return;
      }
      if (state.href.contains("/manage/oauth2/code")) {
        if (browser.engine == BrowserEngine.JCEF) {
          browser.navigate("https://account.jagex.com/en-GB/manage/profile");
        } else {
          cdp.navigate("https://account.jagex.com/en-GB/manage/profile");
        }
        sleep(1500);
        continue;
      }
      if (humanChallengePresent(cdp, state)) {
        if (browser.engine == BrowserEngine.JCEF) {
          browser.reveal();
        }
        if (!waitPastHumanCheck(cdp, "")) {
          throw new IllegalStateException("human check did not clear during login");
        }
        continue;
      }
      if (!dismissCookieNotice(cdp, text).isEmpty()) {
        sleep(500);
        continue;
      }
      if (isAccountLocked(text)) {
        throw new IllegalStateException("Jagex reported the account is locked");
      }
      if (isInvalidCredentials(text)) {
        throw new IllegalStateException("Jagex login failed (invalid credentials): " + brief(state.text));
      }
      if (hasInput(state, "email") && !emailFilled) {
        fillFirst(cdp, Arrays.asList("input[type='email']", "input[name='email']",
            "input[id*='email' i]", "input[autocomplete='email']", "input"), email);
        if (clickText(cdp, Arrays.asList("^continue$", "^next$", "^submit$", "^verify$")).isEmpty()) {
          pressEnter(cdp);
        }
        emailFilled = true;
        sleep(900);
        continue;
      }
      if (hasInput(state, "password") && !passwordFilled) {
        fillFirst(cdp, Arrays.asList("input[type='password']", "input[name='password']",
            "input[id*='password' i]", "input[autocomplete='current-password']"), password);
        if (clickText(cdp, Arrays.asList("^continue$", "^next$", "^submit$", "^verify$")).isEmpty()) {
          pressEnter(cdp);
        }
        passwordFilled = true;
        mailCodeAfter = System.currentTimeMillis() / 1000L - 5L;
        sleep(1_100);
        continue;
      }
      // 2FA method-selection ("Choose a way to verify it's you") — the account has both authenticator
      // and email. Pick EMAIL: we read email codes, whereas the authenticator option is the unreachable
      // shadow modal. (We disable email 2FA right after logging in, leaving authenticator-only.)
      String wide = (text + " " + deepInnerText(cdp)).toLowerCase(Locale.ROOT);
      if (!matches(text, "enter (?:the )?(?:verification|security) code|code sent to")
          && (matches(wide, "choose a way to verify|verify it.?s you")
              || (matches(wide, "use your authenticator app") && matches(wide, "send a code to your email")))) {
        String picked = clickText(cdp, Arrays.asList(
            "send a code to your email", "code to your email address", "to your email address"));
        if (picked.isEmpty()) {
          picked = clickExactButton(cdp, "^(send a code to your email address|use your email address|email address)$");
        }
        if (!picked.isEmpty()) {
          mailCodeAfter = System.currentTimeMillis() / 1000L - 5L;
          sleep(1_300);
          continue;
        }
      }
      boolean emailLoginCodePage = !isAuthenticatorCodePage(text) && !matches(text, "authenticator")
          && (matches(state.href, "email-code-verify") || isEmailCodePage(text)
              || matches(text, "emailed you a verification code|enter the code sent to|code sent to [^ ]+@"));
      if (emailLoginCodePage) {
        if (mailCodeHelper == null || mailCodeHelper.isEmpty()) {
          throw new IllegalStateException("Jagex requires an email login code but no mail-code helper");
        }
        if (emailCodeAttempts >= 4) {
          throw new IllegalStateException("Jagex kept rejecting the emailed login code");
        }
        if (mailCodeAfter == 0L) {
          mailCodeAfter = System.currentTimeMillis() / 1000L - 120L;
        }
        String code = fetchEmailCode(email, mailCodeHelper, mailCodeAfter, lastEmailCode);
        if (code.isEmpty()) {
          throw new IllegalStateException("no Jagex email login code arrived");
        }
        if (code.equalsIgnoreCase(lastEmailCode) && !isRejectedVerificationCode(text)
            && System.currentTimeMillis() - lastEmailCodeAt < 8_000L) {
          sleep(1_000);
          continue;
        }
        boolean filled = false;
        for (int t = 0; t < 5 && !filled; t++) {
          filled = fillCodeDeep(cdp, code);
          if (!filled) {
            sleep(1_200);
          }
        }
        if (!filled) {
          sleep(800);
          continue;
        }
        lastEmailCode = code;
        lastEmailCodeAt = System.currentTimeMillis();
        emailCodeAttempts++;
        sleep(1_800);
        continue;
      }
      sleep(700);
    }
    throw new IllegalStateException("could not reach account management during login");
  }

  // Best-effort: turn off email-based 2FA so the account is authenticator-only (the import login then
  // gets a simple full-page authenticator prompt instead of the unreachable dual-MFA modal).
  void disableEmailMfa(CdpClient cdp, String secret) {
    try {
      String url = "https://account.jagex.com/en-GB/manage/profile";
      if (browser.engine == BrowserEngine.JCEF) {
        browser.navigate(url);
        sleep(4_000);
      } else {
        cdp.navigate(url);
        sleep(1_500);
      }
      long deadline = System.currentTimeMillis() + 150_000L;
      long lastCodeCounter = -1L;
      long lastCodeAt = 0L;
      int codeAttempts = 0;
      int loop = 0;
      int shots = 0;
      String lastAction = "navigating";
      while (System.currentTimeMillis() < deadline) {
        State state = readState(cdp);
        String text = state.text.toLowerCase(Locale.ROOT);
        String all = (text + " " + deepInnerText(cdp)).toLowerCase(Locale.ROOT);
        if (++loop % 6 == 1 && shots < 25) {
          log.accept("disable-email [" + lastAction + "] @ " + brief(state.href) + " :: " + brief(state.text));
          screenshot(cdp, "disable-L" + String.format(Locale.ROOT, "%03d", loop));
          shots++;
        }
        if (humanChallengePresent(cdp, state)) {
          if (browser.engine == BrowserEngine.JCEF) {
            browser.reveal();
          }
          if (!waitPastHumanCheck(cdp, "")) {
            log.accept("disableEmailMfa: human check did not clear");
            return;
          }
          continue;
        }
        if (!dismissCookieNotice(cdp, text).isEmpty()) {
          sleep(500);
          continue;
        }
        if (matches(all, "security codes via email") && !emailMfaEnabled(all)) {
          log.accept("email 2FA disabled");
          return;
        }
        if (isAuthenticatorCodePage(all) || matches(all,
            "enter (?:the )?(?:verification|security) code|confirm.*authenticator|enter your authenticator")) {
          Totp.Code code = freshTotp(secret);
          if (lastCodeAt > 0L && code.counter == lastCodeCounter
              && System.currentTimeMillis() - lastCodeAt < 4_000L) {
            sleep(650);
            continue;
          }
          if (codeAttempts >= 5) {
            log.accept("disableEmailMfa: confirm-code attempts exhausted");
            return;
          }
          if (fillCodeDeep(cdp, code.value)) {
            lastCodeCounter = code.counter;
            lastCodeAt = System.currentTimeMillis();
            codeAttempts++;
            lastAction = "submitted confirm code";
            sleep(1_500);
            continue;
          }
          sleep(700);
          continue;
        }
        String clicked = clickText(cdp, Arrays.asList(
            "disable.{0,30}email", "remove.{0,30}email", "turn off.{0,30}email",
            "yes,? (?:disable|remove|turn off)", "^disable$", "^remove$", "^turn off$", "^confirm$"));
        if (!clicked.isEmpty()) {
          lastAction = "clicked " + brief(clicked);
          sleep(1_300);
          continue;
        }
        String btn = clickExactButton(cdp, "^(disable|remove|turn off|confirm|continue)$");
        if (!btn.isEmpty()) {
          lastAction = "clicked " + btn;
          sleep(1_300);
          continue;
        }
        // The Disable control lives behind the email row's "..." options menu — open it.
        if (clickEmailSectionMenu(cdp)) {
          lastAction = "opened email options menu";
          sleep(1_200);
          continue;
        }
        sleep(800);
      }
      log.accept("disableEmailMfa: timed out (best-effort)");
    } catch (RuntimeException exception) {
      log.accept("disableEmailMfa best-effort error: " + brief(exception.getMessage()));
    }
  }

  private boolean emailMfaEnabled(String text) {
    int start = text.indexOf("security codes via email");
    if (start < 0) {
      return false;
    }
    int end = text.indexOf("backup codes", start);
    String section = end > start ? text.substring(start, end)
        : text.substring(start, Math.min(text.length(), start + 400));
    return matches(section, "added|enabled|active") && !matches(section, "enable\\b");
  }

  // Standalone: log in and disable email-2FA on an already-enrolled account (debug/repair path).
  String disableEmailOnly(String email, String password, String secret, String mailCodeHelper) throws Exception {
    String url = "https://account.jagex.com/";
    boolean nativeJcefNavigation = browser.engine == BrowserEngine.JCEF;
    if (nativeJcefNavigation) {
      browser.navigate(url);
      sleep(6_000);
    }
    try (CdpClient cdp = nativeJcefNavigation ? openPage() : openPage(url)) {
      if (!nativeJcefNavigation) {
        sleep(800);
      }
      loginToAccountManagement(cdp, email, password, mailCodeHelper);
      disableEmailMfa(cdp, secret);
      return "disabled";
    }
  }

  private CdpClient openPage() throws Exception {
    return openPage("about:blank");
  }

  private CdpClient openPage(String initialUrl) throws Exception {
    String ws;
    String targetUrl = (initialUrl == null || initialUrl.isBlank()) ? "about:blank" : initialUrl;
    if (browser.engine == BrowserEngine.JCEF) {
      try {
        ws = CdpClient.pageWebSocket(browser.endpoint);
      } catch (Exception exception) {
        ws = CdpClient.newPage(browser.endpoint, "about:blank");
      }
    } else {
      try {
        ws = CdpClient.newPage(browser.endpoint, targetUrl);
      } catch (Exception exception) {
        ws = CdpClient.pageWebSocket(browser.endpoint);
      }
    }
    CdpClient cdp = CdpClient.connect(ws);
    cdp.send("Runtime.enable");
    cdp.send("Page.enable");
    cdp.send("Network.enable");
    if (!BLOCKED_URL_PATTERNS.isEmpty()) {
      LinkedHashMap<String, Object> params = new LinkedHashMap<>();
      params.put("urls", BLOCKED_URL_PATTERNS);
      try {
        cdp.send("Network.setBlockedURLs", params);
      } catch (RuntimeException exception) {
        log.accept("could not install importer blocked-url patterns: " + brief(exception.getMessage()));
      }
    }
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

  private boolean humanChallengePresent(CdpClient cdp, State state) {
    String combined = (state.text + " " + deepInnerText(cdp)).toLowerCase(Locale.ROOT);
    if (matches(combined, "are you a robot|verify you are human|security check|checking your browser"
        + "|turnstile|captcha|cloudflare")) {
      return true;
    }
    try {
      for (CdpClient.Target target : CdpClient.targets(browser.endpoint)) {
        String targetText = (target.type + " " + target.title + " " + target.url).toLowerCase(Locale.ROOT);
        if ("iframe".equalsIgnoreCase(target.type)
            && matches(targetText, "cloudflare|challenge|turnstile|captcha|human|verify")) {
          return true;
        }
      }
    } catch (Exception ignored) {
      // Fall through to the DOM probe.
    }
    try {
      Object domChallenge = cdp.evaluate("(() => Array.from(document.querySelectorAll('iframe')).some((iframe)=>{"
          + "const joined=[iframe.title,iframe.name,iframe.id,iframe.src,iframe.getAttribute('aria-label')].join(' ').toLowerCase();"
          + "const r=iframe.getBoundingClientRect();"
          + "return r.width>0&&r.height>0&&/cloudflare|challenge|turnstile|captcha|human|verify/.test(joined);"
          + "}))()");
      if (Boolean.TRUE.equals(domChallenge)) {
        return true;
      }
    } catch (RuntimeException ignored) {
      // Best effort only.
    }
    return false;
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
      if (!humanChallengePresent(cdp, state)) {
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
    int runtimeTimeouts = 0;
    for (int attempt = 0; attempt < 30; attempt++) {
      try {
        return State.from(Json.asObject(cdp.evaluate(stateScript())));
      } catch (RuntimeException exception) {
        last = exception;
        String message = String.valueOf(exception.getMessage()).toLowerCase(Locale.ROOT);
        if (!(message.contains("execution context was destroyed")
            || message.contains("cannot find context")
            || message.contains("frame was detached")
            || message.contains("timed out"))) {
          throw exception;
        }
        if (message.contains("timed out")) {
          runtimeTimeouts++;
          if (runtimeTimeouts >= 1) {
            throw exception;
          }
        }
        sleep(350L);
      }
    }
    throw last == null ? new IllegalStateException("could not read browser state") : last;
  }

  private boolean hasInput(State state, String regex) {
    Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    for (Map<String, Object> input : state.inputs) {
      String joined = inputMetadata(input);
      if (pattern.matcher(joined).find()) {
        return true;
      }
    }
    return false;
  }

  private boolean codeInputReady(State state) {
    for (Map<String, Object> input : state.inputs) {
      if (looksLikeVerificationCodeInput(input)) {
        return true;
      }
    }
    return false;
  }

  private String inputMetadata(Map<String, Object> input) {
    return (Json.string(input.get("type")) + " "
        + Json.string(input.get("name")) + " "
        + Json.string(input.get("id")) + " "
        + Json.string(input.get("autocomplete")) + " "
        + Json.string(input.get("placeholder")) + " "
        + Json.string(input.get("aria")) + " "
        + Json.string(input.get("inputMode"))).toLowerCase(Locale.ROOT);
  }

  private boolean looksLikeVerificationCodeInput(Map<String, Object> input) {
    String type = Json.string(input.get("type")).toLowerCase(Locale.ROOT);
    String joined = inputMetadata(input);
    if (matches(type, "hidden|checkbox|radio|submit|button")) {
      return false;
    }
    if (matches(joined, "email|password|search|locale")) {
      return false;
    }
    if (matches(joined, "code|otp|totp|verification|one-time|authenticator")) {
      return true;
    }
    int maxLength = inputMaxLength(input);
    return maxLength > 0 && maxLength <= 8 && matches(type + " " + joined, "tel|number|numeric");
  }

  private int inputMaxLength(Map<String, Object> input) {
    Object raw = input.get("maxLength");
    if (raw == null) {
      return 0;
    }
    return Json.number(raw).intValue();
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
    Map<String, Object> point = Json.asObject(cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const selectors=" + Json.stringify(selectors) + ";"
        + "const el=candidates(selectors)[0];"
        + "if(!el)return null;"
        + "el.scrollIntoView({block:'center',inline:'center'});"
        + "const r=el.getBoundingClientRect();"
        + "return {x:r.left+r.width/2,y:r.top+r.height/2};"
        + "})()"));
    if (point.isEmpty()) {
      throw new IllegalStateException("could not find visible input on Jagex login page");
    }
    clickPoint(cdp, point);
    selectExistingInputText(cdp);
    insertText(cdp, value);
    sleep(300);
    Object filled = cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const selectors=" + Json.stringify(selectors) + ";"
        + "const el=candidates(selectors)[0];"
        + "if(!el)return false;"
        + "return String(el.value||'')===" + Json.quote(value) + ";"
        + "})()");
    if (!Boolean.TRUE.equals(filled)) {
      Object fallback = cdp.evaluate("(() => {"
          + visibleHelpers()
          + "const selectors=" + Json.stringify(selectors) + ";"
          + "const el=candidates(selectors)[0];"
          + "if(!el)return false;"
          + "setValue(el," + Json.quote(value) + ");"
          + "return true;"
          + "})()");
      if (!Boolean.TRUE.equals(fallback)) {
        throw new IllegalStateException("could not fill visible input on Jagex login page");
      }
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

  // Click a clickable element (button/link/role=button) whose OWN short text matches the regex,
  // piercing shadow roots. Unlike clickText this never matches container divs/spans, so it hits the
  // small "Enable" button on the account-management page without grabbing a whole section blob.
  private String clickExactButton(CdpClient cdp, String regex) {
    Map<String, Object> point = Json.asObject(cdp.evaluate("(() => {"
        + "const visible=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const deep=(sel)=>{const out=[];const seen=new Set();const visit=(root)=>{"
        + "if(!root||seen.has(root))return;seen.add(root);"
        + "if(root.querySelectorAll){root.querySelectorAll(sel).forEach((el)=>out.push(el));"
        + "root.querySelectorAll('*').forEach((el)=>{if(el.shadowRoot)visit(el.shadowRoot);});}};"
        + "visit(document);return out;};"
        + "const norm=(v)=>String(v||'').replace(/\\s+/g,' ').trim();"
        + "const re=new RegExp(" + Json.quote(regex) + ",'i');"
        + "const btns=deep('button,a,[role=\"button\"],input[type=\"submit\"],input[type=\"button\"]').filter(visible);"
        + "const hit=btns.find((el)=>re.test(norm(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent)));"
        + "if(!hit)return null;hit.scrollIntoView({block:'center',inline:'center'});"
        + "const r=hit.getBoundingClientRect();"
        + "return {x:r.left+r.width/2,y:r.top+r.height/2,"
        + "text:norm(hit.innerText||hit.value||hit.getAttribute('aria-label')||hit.textContent)||'button'};"
        + "})()"));
    if (point.isEmpty()) {
      return "";
    }
    clickPoint(cdp, point);
    return Json.string(point.get("text"));
  }

  // Click the "..." options menu aligned with the "Security codes via email" heading (it lives in a
  // separate layout column, so target the small icon button nearest that heading's vertical centre).
  private boolean clickEmailSectionMenu(CdpClient cdp) {
    Map<String, Object> point = Json.asObject(cdp.evaluate("(() => {"
        + "const vis=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const norm=(v)=>String(v||'').replace(/\\s+/g,' ').trim();"
        + "const heads=Array.from(document.querySelectorAll('*')).filter((el)=>vis(el)"
        + "&&/^security codes via email$/i.test(norm(el.innerText||el.textContent)));"
        + "if(!heads.length)return null;"
        + "const hr=heads[0].getBoundingClientRect();const ey=hr.top+hr.height/2;"
        + "const cands=Array.from(document.querySelectorAll('button,[role=\"button\"],[aria-haspopup],a,span,div'))"
        + ".filter(vis).filter((b)=>{const t=norm(b.innerText||b.textContent);"
        + "const lab=norm(b.getAttribute&&(b.getAttribute('aria-label')||''));"
        + "const cur=getComputedStyle(b).cursor;const rr=b.getBoundingClientRect();"
        + "const small=rr.width<70&&rr.height<70;"
        + "const clickable=b.tagName==='BUTTON'||b.getAttribute('role')==='button'"
        + "||(b.hasAttribute&&b.hasAttribute('aria-haspopup'))||cur==='pointer';"
        + "const menuish=t===''||/^[.\\u2026\\u22ef\\u00b7]+$/.test(t)||/option|menu|more|action|manage/i.test(lab);"
        + "return small&&clickable&&menuish;});"
        + "if(!cands.length)return null;"
        + "cands.sort((a,b)=>{const ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();"
        + "return Math.abs(ar.top+ar.height/2-ey)-Math.abs(br.top+br.height/2-ey);});"
        + "const menu=cands[0];const mr=menu.getBoundingClientRect();"
        + "const dy=Math.abs(mr.top+mr.height/2-ey);"
        + "menu.scrollIntoView({block:'center',inline:'center'});"
        + "const r=menu.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2,dy:dy};"
        + "})()"));
    if (point.isEmpty()) {
      return false;
    }
    double dy = point.get("dy") == null ? 999 : Json.number(point.get("dy")).doubleValue();
    if (dy > 130) {
      return false;
    }
    clickPoint(cdp, point);
    return true;
  }

  private String dismissCookieNotice(CdpClient cdp, String text) {
    List<String> patterns = Arrays.asList(
        "use necessary cookies only",
        "allow all cookies",
        "accept all cookies",
        "^accept all$",
        "^accept$",
        "^agree$",
        "confirm choices",
        "save choices",
        "reject all");
    if (isCookieNotice(text)) {
      String clicked = clickText(cdp, patterns);
      if (!clicked.isEmpty()) {
        return clicked;
      }
      clicked = clickExactButton(cdp, "^(use necessary cookies only|allow all cookies|accept all cookies|accept all|accept|agree|confirm choices|save choices|reject all)$");
      if (!clicked.isEmpty()) {
        return clicked;
      }
    }
    try {
      for (CdpClient.Target target : CdpClient.targets(browser.endpoint)) {
        String targetText = (target.type + " " + target.title + " " + target.url).toLowerCase(Locale.ROOT);
        if (!"iframe".equalsIgnoreCase(target.type)
            || target.webSocketUrl.isEmpty()
            || !matches(targetText, "cookiebot|consent|cookie")) {
          continue;
        }
        try (CdpClient frame = CdpClient.connect(target.webSocketUrl)) {
          frame.send("Runtime.enable");
          frame.send("Page.enable");
          frame.send("Network.enable");
          String clicked = clickText(frame, patterns);
          if (clicked.isEmpty()) {
            clicked = clickExactButton(frame, "^(use necessary cookies only|allow all cookies|accept all cookies|accept all|accept|agree|confirm choices|save choices|reject all)$");
          }
          if (!clicked.isEmpty()) {
            return "iframe " + clicked;
          }
        } catch (RuntimeException exception) {
          log.accept("could not click cookie iframe target: " + brief(exception.getMessage()));
        }
      }
    } catch (Exception exception) {
      log.accept("could not inspect cookie iframe targets: " + brief(exception.getMessage()));
    }
    return "";
  }

  private String clickHumanCheckProceed(CdpClient cdp) {
    String clicked = clickHumanCheckProceedInContext(cdp, true);
    if (!clicked.isEmpty()) {
      return clicked;
    }
    clicked = clickHumanCheckIframeFallback(cdp);
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
          if (clicked.isEmpty()) {
            clicked = clickHumanCheckIframeFallback(frame);
          }
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

  private String clickHumanCheckIframeFallback(CdpClient cdp) {
    Map<String, Object> point = Json.asObject(cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const frame=Array.from(document.querySelectorAll('iframe')).filter(visible).find((iframe)=>{"
        + "const joined=[iframe.title,iframe.name,iframe.id,iframe.src,iframe.getAttribute('aria-label')].join(' ');"
        + "return /cloudflare|challenge|turnstile|captcha|human|verify/i.test(joined);});"
        + "if(!frame)return null;frame.scrollIntoView({block:'center',inline:'center'});"
        + "const r=frame.getBoundingClientRect();"
        + "return {x:r.left,y:r.top,w:r.width,h:r.height};"
        + "})()"));
    if (point.isEmpty()) {
      return "";
    }
    double x = Json.number(point.get("x")).doubleValue();
    double y = Json.number(point.get("y")).doubleValue();
    double w = Math.max(40.0, Json.number(point.get("w")).doubleValue());
    double h = Math.max(40.0, Json.number(point.get("h")).doubleValue());
    double[][] offsets = new double[][] {
        {0.10, 0.52},
        {0.14, 0.52},
        {0.18, 0.52},
        {0.10, 0.62},
    };
    for (double[] offset : offsets) {
      double px = x + Math.max(14.0, Math.min(w - 14.0, w * offset[0]));
      double py = y + Math.max(14.0, Math.min(h - 14.0, h * offset[1]));
      cdp.send("Input.dispatchMouseEvent", mouse("mouseMoved", px, py));
      cdp.send("Input.dispatchMouseEvent", mouse("mousePressed", px, py, "left", 1));
      sleep(110);
      cdp.send("Input.dispatchMouseEvent", mouse("mouseReleased", px, py, "left", 1));
      sleep(250);
    }
    return "challenge frame fallback";
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

  // Types the code into the authenticator field(s) using real key events (synthetic value-setting is
  // ignored by Jagex's controlled segmented input), confirms the digits landed, then submits.
  // Returns false if the typed code could not be read back from the field (an entry failure, as
  // opposed to Jagex rejecting a code that was entered correctly).
  private boolean fillCodeAndSubmit(CdpClient cdp, String code) {
    return fillCodeAndSubmit(cdp, code, false);
  }

  private boolean fillCodeAndSubmit(CdpClient cdp, String code, boolean emailLogin) {
    Map<String, Object> target = Json.asObject(cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const meta=(el)=>[el.type,el.name,el.id,el.autocomplete,el.placeholder,el.getAttribute('aria-label'),el.inputMode].join(' ');"
        + "const bad=(el)=>/" + (emailLogin ? "" : "email|") + "password|hidden|checkbox|radio|submit|button/i.test(meta(el));"
        + "const inputs=Array.from(document.querySelectorAll('input')).filter(visible)"
        + ".filter((input)=>!bad(input)&&!input.disabled&&input.getAttribute('aria-disabled')!=='true');"
        + "const scored=inputs.map((input,index)=>{"
        + "const joined=meta(input);"
        + "const codeish=/code|otp|totp|auth|security|verification|one-time|numeric/i.test(joined)?5:0;"
        + "const short=Number(input.maxLength||0)>0&&Number(input.maxLength||0)<=8?2:0;"
        + "const numeric=/tel|number|numeric/i.test(joined)?1:0;"
        + "return {input,index,score:codeish+short+numeric};"
        + "}).sort((a,b)=>b.score-a.score||a.index-b.index);"
        + "if(scored.length===0)return null;"
        + "const codeLength=" + code.length() + ";"
        + "const usable=scored.map((item)=>item.input);"
        + "const split=usable.length>=codeLength&&usable.slice(0,codeLength).every((input)=>Number(input.maxLength||1)<=1);"
        + "const chosen=split?usable.slice(0,codeLength):[usable[0]];"
        + "return {split,targets:chosen.map((input)=>{"
        + "input.scrollIntoView({block:'center',inline:'center'});"
        + "const r=input.getBoundingClientRect();"
        + "return {x:r.left+r.width/2,y:r.top+r.height/2};"
        + "})};"
        + "})()"));
    if (target.isEmpty()) {
      throw new IllegalStateException("could not find Jagex authenticator-code input");
    }
    List<Object> targets = Json.asList(target.get("targets"));
    if (targets.isEmpty()) {
      throw new IllegalStateException("could not find Jagex authenticator-code input");
    }
    boolean split = Boolean.TRUE.equals(target.get("split"));
    if (split) {
      for (int i = 0; i < Math.min(code.length(), targets.size()); i++) {
        clickPoint(cdp, Json.asObject(targets.get(i)));
        typeDigit(cdp, code.charAt(i));
        sleep(70);
      }
    } else {
      clickPoint(cdp, Json.asObject(targets.get(0)));
      selectExistingInputText(cdp);
      typeDigits(cdp, code);
    }
    sleep(350);
    if (!authenticatorCodeWasTyped(cdp, code)) {
      return false;
    }
    log.accept("typed authenticator code into Jagex code input (split " + split + ")");
    Map<String, Object> button = Json.asObject(cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const button=Array.from(document.querySelectorAll('button,input[type=\"submit\"],[role=\"button\"]')).filter(visible)"
        + ".find((el)=>{const text=normalize(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent);"
        + "const disabled=el.disabled||el.getAttribute('aria-disabled')==='true';"
        + "return !disabled&&/continue|verify|submit|confirm|next/i.test(text);});"
        + "if(!button)return null;"
        + "button.scrollIntoView({block:'center',inline:'center'});"
        + "const r=button.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2};"
        + "})()"));
    if (button.isEmpty()) {
      // Some flows auto-submit once the final digit is entered; press Enter as a fallback.
      pressEnter(cdp);
      return true;
    }
    clickPoint(cdp, button);
    return true;
  }

  private void clickPoint(CdpClient cdp, Map<String, Object> point) {
    double x = Json.number(point.get("x")).doubleValue();
    double y = Json.number(point.get("y")).doubleValue();
    cdp.send("Input.dispatchMouseEvent", mouse("mouseMoved", x, y));
    cdp.send("Input.dispatchMouseEvent", mouse("mousePressed", x, y, "left", 1));
    cdp.send("Input.dispatchMouseEvent", mouse("mouseReleased", x, y, "left", 1));
  }

  private boolean authenticatorCodeWasTyped(CdpClient cdp, String code) {
    Object result = cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const meta=(el)=>[el.type,el.name,el.id,el.autocomplete,el.placeholder,el.getAttribute('aria-label'),el.inputMode].join(' ');"
        + "const bad=(el)=>/email|password|hidden|checkbox|radio|submit|button/i.test(meta(el));"
        + "const values=Array.from(document.querySelectorAll('input')).filter(visible)"
        + ".filter((input)=>!bad(input)&&!input.disabled&&input.getAttribute('aria-disabled')!=='true')"
        + ".map((input)=>String(input.value||'')).filter(Boolean);"
        + "const joined=values.join('');"
        + "return joined.includes(" + Json.quote(code) + ") || values.includes(" + Json.quote(code) + ");"
        + "})()");
    return Boolean.TRUE.equals(result);
  }

  private int visibleInputValueLength(CdpClient cdp, List<String> selectors) {
    Object result = cdp.evaluate("(() => {"
        + visibleHelpers()
        + "const selectors=" + Json.stringify(selectors) + ";"
        + "const el=candidates(selectors)[0];"
        + "if(!el)return -1;"
        + "return String(el.value||'').length;"
        + "})()");
    return result == null ? -1 : Json.number(result).intValue();
  }

  private boolean deepInputContainsCode(CdpClient cdp, String code) {
    Object result = cdp.evaluate("(() => {"
        + "const visible=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const deep=(sel)=>{const out=[];const seen=new Set();const visit=(root)=>{"
        + "if(!root||seen.has(root))return;seen.add(root);"
        + "if(root.querySelectorAll){root.querySelectorAll(sel).forEach((el)=>out.push(el));"
        + "root.querySelectorAll('*').forEach((el)=>{if(el.shadowRoot)visit(el.shadowRoot);});}};"
        + "visit(document);return out;};"
        + "const meta=(el)=>[el.type,el.name,el.id,el.autocomplete,el.placeholder,"
        + "el.getAttribute('aria-label'),el.inputMode].join(' ');"
        + "const bad=(el)=>/password|hidden|checkbox|radio|submit|button/i.test(meta(el));"
        + "const values=deep('input').filter(visible)"
        + ".filter((input)=>!bad(input)&&!input.disabled&&input.getAttribute('aria-disabled')!=='true')"
        + ".map((input)=>String(input.value||'')).filter(Boolean);"
        + "const joined=values.join('');"
        + "return joined.includes(" + Json.quote(code) + ") || values.includes(" + Json.quote(code) + ");"
        + "})()");
    return Boolean.TRUE.equals(result);
  }

  private String visibleCodeInputDebug(CdpClient cdp) {
    Object result = cdp.evaluate("(() => {"
        + "const visible=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const normalize=(v)=>String(v||'').replace(/\\s+/g,' ').trim();"
        + "const values=Array.from(document.querySelectorAll('input,textarea,[contenteditable=\"true\"],[role=\"textbox\"],[role=\"spinbutton\"]'))"
        + ".filter(visible).slice(0,16).map((el)=>({"
        + "tag:String(el.tagName||'').toLowerCase(),"
        + "type:normalize(el.type||''),"
        + "id:normalize(el.id||''),"
        + "name:normalize(el.name||''),"
        + "autocomplete:normalize(el.autocomplete||''),"
        + "placeholder:normalize(el.placeholder||''),"
        + "aria:normalize(el.getAttribute&&el.getAttribute('aria-label')||''),"
        + "maxLength:Number(el.maxLength||0),"
        + "valueLength:String(el.value||'').length"
        + "}));"
        + "return JSON.stringify(values);"
        + "})()");
    String text = Json.string(result);
    return text == null ? "" : text;
  }

  private String truncate(String value, int max) {
    if (value == null) {
      return "";
    }
    if (value.length() <= max) {
      return value;
    }
    return value.substring(0, max);
  }

  // Jagex's code fields (email-login code, authenticator-setup confirm) can live inside a custom
  // element's shadow root, which a plain querySelectorAll('input') (fillCodeAndSubmit) misses.
  // Pierce open shadow roots. Allows email-metadata inputs (no email field on these pages).
  private boolean fillCodeDeep(CdpClient cdp, String code) {
    String deepHelper = "const visible=(el)=>{if(!el)return false;const s=getComputedStyle(el);"
        + "if(s.visibility==='hidden'||s.display==='none')return false;"
        + "const r=el.getBoundingClientRect();return r.width>0&&r.height>0;};"
        + "const deep=(sel)=>{const out=[];const seen=new Set();const visit=(root)=>{"
        + "if(!root||seen.has(root))return;seen.add(root);"
        + "if(root.querySelectorAll){root.querySelectorAll(sel).forEach((el)=>out.push(el));"
        + "root.querySelectorAll('*').forEach((el)=>{if(el.shadowRoot)visit(el.shadowRoot);});}};"
        + "visit(document);return out;};"
        + "const candidates=(selectors)=>selectors.flatMap((selector)=>deep(selector)).filter(visible);"
        + "const setValue=(el,value)=>{el.focus();const d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');"
        + "if(d&&d.set){d.set.call(el,value);}else{el.value=value;}"
        + "el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};"
        + "const normalize=(v)=>String(v||'').replace(/\\s+/g,' ').trim();";
    Map<String, Object> direct = Json.asObject(cdp.evaluate("(() => {"
        + deepHelper
        + "const selectors=['input#registration-verify-form-code-input','input#email-code-verify-form--input-code',"
        + "'input#totp-verify-form--input-code','input#authentication-setup-verification-code',"
        + "\"input[name='code']\",'input[id*=\"totp\" i]','input[id*=\"verification-code\" i]',"
        + "'input[aria-label*=\"verification code\" i]','input[autocomplete=\"one-time-code\"]'];"
        + "for(const selector of selectors){"
        + " const input=document.querySelector(selector);"
        + " if(!input||!visible(input)||input.disabled||input.getAttribute('aria-disabled')==='true') continue;"
        + " input.scrollIntoView({block:'center',inline:'center'});"
        + " const r=input.getBoundingClientRect();"
        + " return {x:r.left+r.width/2,y:r.top+r.height/2};"
        + "}"
        + "return null;"
        + "})()"));
    if (!direct.isEmpty()) {
      List<String> directSelectors = Arrays.asList(
          "input#registration-verify-form-code-input",
          "input#email-code-verify-form--input-code",
          "input#totp-verify-form--input-code",
          "input#authentication-setup-verification-code",
          "input[name='code']",
          "input[id*='totp' i]",
          "input[id*='verification-code' i]",
          "input[aria-label*='verification code' i]",
          "input[autocomplete='one-time-code']");
      clickPoint(cdp, direct);
      selectExistingInputText(cdp);
      typeDigits(cdp, code);
      sleep(400);
      int typedLength = visibleInputValueLength(cdp, directSelectors);
      if (typedLength < code.length()) {
        clickPoint(cdp, direct);
        selectExistingInputText(cdp);
        insertText(cdp, code);
        sleep(250);
        typedLength = visibleInputValueLength(cdp, directSelectors);
      }
      if (typedLength < code.length()) {
        Object fallback = cdp.evaluate("(() => {"
            + deepHelper
            + "const selectors=" + Json.stringify(directSelectors) + ";"
            + "const el=candidates(selectors)[0];"
            + "if(!el)return false;"
            + "setValue(el," + Json.quote(code) + ");"
            + "return true;"
            + "})()");
        if (Boolean.TRUE.equals(fallback)) {
          sleep(250);
          typedLength = visibleInputValueLength(cdp, directSelectors);
        }
      }
      if (typedLength >= code.length()) {
        Object sync = cdp.evaluate("(() => {"
            + deepHelper
            + "const selectors=" + Json.stringify(directSelectors) + ";"
            + "const el=candidates(selectors)[0];"
            + "if(!el)return false;"
            + "setValue(el," + Json.quote(code) + ");"
            + "return true;"
            + "})()");
        if (Boolean.TRUE.equals(sync)) {
          sleep(150);
          typedLength = visibleInputValueLength(cdp, directSelectors);
        }
      }
      log.accept("direct code input value length " + typedLength + "/" + code.length());
      if (typedLength < code.length()) {
        log.accept("direct code input did not retain the full code; trying deep input fallback");
      } else {
      Map<String, Object> button = Json.asObject(cdp.evaluate("(() => {"
          + deepHelper
          + "const button=deep('button,input[type=\"submit\"],[role=\"button\"]').filter(visible)"
          + ".find((el)=>{const text=normalize(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent);"
          + "const disabled=el.disabled||el.getAttribute('aria-disabled')==='true';"
          + "return !disabled&&/continue|verify|submit|confirm|next/i.test(text);});"
          + "if(!button)return null;button.scrollIntoView({block:'center',inline:'center'});"
          + "const r=button.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2};"
          + "})()"));
      if (button.isEmpty()) {
        pressEnter(cdp);
      } else {
        clickPoint(cdp, button);
      }
      return true;
      }
    }
    Map<String, Object> target = Json.asObject(cdp.evaluate("(() => {"
        + deepHelper
        + "const meta=(el)=>[el.type,el.name,el.id,el.autocomplete,el.placeholder,el.getAttribute('aria-label'),el.inputMode].join(' ');"
        + "const bad=(el)=>/password|hidden|checkbox|radio|submit|button/i.test(meta(el));"
        + "const inputs=deep('input').filter(visible).filter((el)=>!bad(el)&&!el.disabled&&el.getAttribute('aria-disabled')!=='true');"
        + "const scored=inputs.map((input,index)=>{const joined=meta(input);"
        + "const codeish=/code|otp|totp|auth|security|verification|one-time|numeric/i.test(joined)?5:0;"
        + "const short=Number(input.maxLength||0)>0&&Number(input.maxLength||0)<=8?2:0;"
        + "const numeric=/tel|number|numeric/i.test(joined)?1:0;"
        + "return {input,index,score:codeish+short+numeric};}).sort((a,b)=>b.score-a.score||a.index-b.index);"
        + "if(scored.length===0)return null;"
        + "const codeLength=" + code.length() + ";"
        + "const usable=scored.map((item)=>item.input);"
        + "const split=usable.length>=codeLength&&usable.slice(0,codeLength).every((input)=>Number(input.maxLength||1)<=1);"
        + "const chosen=split?usable.slice(0,codeLength):[usable[0]];"
        + "return {split,targets:chosen.map((input)=>{input.scrollIntoView({block:'center',inline:'center'});"
        + "const r=input.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2};})};"
        + "})()"));
    if (target.isEmpty()) {
      log.accept("deep code input target search found no usable inputs: " + truncate(visibleCodeInputDebug(cdp), 1200));
      return false;
    }
    List<Object> targets = Json.asList(target.get("targets"));
    if (targets.isEmpty()) {
      log.accept("deep code input target search produced an empty target list: " + truncate(visibleCodeInputDebug(cdp), 1200));
      return false;
    }
    boolean split = Boolean.TRUE.equals(target.get("split"));
    if (split) {
      for (int i = 0; i < Math.min(code.length(), targets.size()); i++) {
        clickPoint(cdp, Json.asObject(targets.get(i)));
        typeDigit(cdp, code.charAt(i));
        sleep(70);
      }
    } else {
      clickPoint(cdp, Json.asObject(targets.get(0)));
      selectExistingInputText(cdp);
      typeDigits(cdp, code);
    }
    sleep(350);
    if (!deepInputContainsCode(cdp, code)) {
      log.accept("deep code input did not retain the submitted code; visible inputs "
          + truncate(visibleCodeInputDebug(cdp), 1200));
      return false;
    }
    Map<String, Object> button = Json.asObject(cdp.evaluate("(() => {"
        + deepHelper
        + "const button=deep('button,input[type=\"submit\"],[role=\"button\"]').filter(visible)"
        + ".find((el)=>{const text=normalize(el.innerText||el.value||el.getAttribute('aria-label')||el.textContent);"
        + "const disabled=el.disabled||el.getAttribute('aria-disabled')==='true';"
        + "return !disabled&&/continue|verify|submit|confirm|next/i.test(text);});"
        + "if(!button)return null;button.scrollIntoView({block:'center',inline:'center'});"
        + "const r=button.getBoundingClientRect();return {x:r.left+r.width/2,y:r.top+r.height/2};"
        + "})()"));
    if (button.isEmpty()) {
      pressEnter(cdp);
      return true;
    }
    clickPoint(cdp, button);
    return true;
  }

  private void typeDigits(CdpClient cdp, String text) {
    for (int i = 0; i < text.length(); i++) {
      typeDigit(cdp, text.charAt(i));
      sleep(40);
    }
  }

  private void insertText(CdpClient cdp, String text) {
    LinkedHashMap<String, Object> params = new LinkedHashMap<>();
    params.put("text", text);
    cdp.send("Input.insertText", params);
  }

  private void typeDigit(CdpClient cdp, char digit) {
    String value = String.valueOf(digit);
    int keyCode = digit;
    String code = Character.isDigit(digit) ? "Digit" + digit : "Key" + Character.toUpperCase(digit);
    LinkedHashMap<String, Object> keyDown = new LinkedHashMap<>();
    keyDown.put("type", "keyDown");
    keyDown.put("windowsVirtualKeyCode", keyCode);
    keyDown.put("nativeVirtualKeyCode", keyCode);
    keyDown.put("code", code);
    keyDown.put("key", value);
    keyDown.put("text", value);
    keyDown.put("unmodifiedText", value);
    cdp.send("Input.dispatchKeyEvent", keyDown);
    LinkedHashMap<String, Object> keyUp = new LinkedHashMap<>();
    keyUp.put("type", "keyUp");
    keyUp.put("windowsVirtualKeyCode", keyCode);
    keyUp.put("nativeVirtualKeyCode", keyCode);
    keyUp.put("code", code);
    keyUp.put("key", value);
    cdp.send("Input.dispatchKeyEvent", keyUp);
  }

  private void selectExistingInputText(CdpClient cdp) {
    LinkedHashMap<String, Object> selectDown = new LinkedHashMap<>();
    selectDown.put("type", "rawKeyDown");
    selectDown.put("windowsVirtualKeyCode", 65);
    selectDown.put("nativeVirtualKeyCode", 65);
    selectDown.put("code", "KeyA");
    selectDown.put("key", "a");
    selectDown.put("modifiers", 2);
    cdp.send("Input.dispatchKeyEvent", selectDown);
    LinkedHashMap<String, Object> selectUp = new LinkedHashMap<>(selectDown);
    selectUp.put("type", "keyUp");
    cdp.send("Input.dispatchKeyEvent", selectUp);

    LinkedHashMap<String, Object> backspaceDown = new LinkedHashMap<>();
    backspaceDown.put("type", "rawKeyDown");
    backspaceDown.put("windowsVirtualKeyCode", 8);
    backspaceDown.put("nativeVirtualKeyCode", 8);
    backspaceDown.put("code", "Backspace");
    backspaceDown.put("key", "Backspace");
    cdp.send("Input.dispatchKeyEvent", backspaceDown);
    LinkedHashMap<String, Object> backspaceUp = new LinkedHashMap<>(backspaceDown);
    backspaceUp.put("type", "keyUp");
    cdp.send("Input.dispatchKeyEvent", backspaceUp);
  }

  private void pressEnter(CdpClient cdp) {
    LinkedHashMap<String, Object> down = new LinkedHashMap<>();
    down.put("type", "keyDown");
    down.put("windowsVirtualKeyCode", 13);
    down.put("nativeVirtualKeyCode", 13);
    down.put("code", "Enter");
    down.put("key", "Enter");
    down.put("text", "\r");
    cdp.send("Input.dispatchKeyEvent", down);
    LinkedHashMap<String, Object> up = new LinkedHashMap<>(down);
    up.put("type", "keyUp");
    up.remove("text");
    cdp.send("Input.dispatchKeyEvent", up);
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
        + "autocomplete:input.autocomplete||'',placeholder:input.placeholder||'',"
        + "aria:(input.getAttribute('aria-label')||''),inputMode:input.inputMode||'',"
        + "maxLength:input.maxLength||0})).slice(0,30),"
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

  // The Jagex authenticator-code prompt: "Please enter the code from your authenticator app...".
  private boolean isAuthenticatorCodePage(String text) {
    return matches(text, "code from your authenticator app|authenticator app to continue"
        + "|code (?:from|generated by) (?:your )?authenticator")
        || (matches(text, "authenticator")
            && matches(text, "verification code|enter (?:the )?code|security code"));
  }

  // The Jagex email-code prompt: "...code sent to your email address". A method-choice page mentions
  // the authenticator too, so exclude anything that references it (handled separately as a choice).
  private boolean isEmailCodePage(String text) {
    return !matches(text, "authenticator")
        && matches(text, "sent to your email|code to your email|check your email"
            + "|enter the code[^.]{0,40}email|code we (?:sent|emailed)")
        && matches(text, "verification code|enter (?:the )?code|security code|enter code");
  }

  private String stateFingerprint(State state) {
    return brief(state.href) + "|" + brief(state.text) + "|i=" + state.inputs.size()
        + "|a=" + state.actions.size() + "|l=" + state.links.size();
  }

  private boolean isBlankSpinnerState(State state) {
    return state.inputs.isEmpty() && state.actions.isEmpty() && state.links.isEmpty()
        && String.valueOf(state.text == null ? "" : state.text).isBlank();
  }

  private boolean passwordSubmitLooksRejected(String text) {
    return matches(text, "incorrect|invalid|problem occurred when trying to log you in"
        + "|technical difficulties|try again later|temporarily unavailable|service unavailable"
        + "|too many requests|tried to do that too many times|account is locked|locked your account");
  }

  private boolean oauthSpinnerStalled(State state, String text, String lastAction, long lastActionAt,
      long sameStateSince, long now) {
    if (sameStateSince <= 0L) {
      return false;
    }
    long sameStateFor = now - sameStateSince;
    long actionAge = now - lastActionAt;
    if (isBlankSpinnerState(state)) {
      long threshold = isConsentChallengePage(state.href) ? 60_000L : 12_000L;
      return sameStateFor >= threshold;
    }
    if (actionAge < 12_000L) {
      return false;
    }
    if ("submitted password".equals(lastAction)
        && hasInput(state, "password")
        && matches(text, "log into your jagex account|enter your password to continue")) {
      return true;
    }
    if (lastAction.startsWith("clicked ")
        && matches(text, "consent|allow|authorize|permission|return to launcher|logging in to jagex launcher")) {
      return sameStateFor >= 12_000L;
    }
    if ("waiting for OAuth callback state".equals(lastAction) && looksLikeOAuthCallback(state.href)) {
      return sameStateFor >= 12_000L;
    }
    return false;
  }

  private boolean looksLikeOAuthCallback(String url) {
    String text = String.valueOf(url == null ? "" : url).toLowerCase(Locale.ROOT);
    return text.contains("code=") || text.contains("id_token=");
  }

  private boolean isConsentChallengePage(String url) {
    String text = String.valueOf(url == null ? "" : url).toLowerCase(Locale.ROOT);
    return text.contains("account.jagex.com/consent") && text.contains("consent_challenge=");
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
