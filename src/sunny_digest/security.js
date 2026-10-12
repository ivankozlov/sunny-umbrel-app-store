(() => {
  "use strict";
  const root = document.getElementById("secure-root");
  if (!root) return;
  const error = document.getElementById("security-error");
  if (!window.isSecureContext || location.origin !== root.dataset.origin) {
    error.hidden = false;
    error.textContent = "Откройте приложение по настроенному HTTPS-адресу: " + root.dataset.origin;
    document.querySelectorAll("button,input,select,textarea").forEach(item => { item.disabled = true; });
    return;
  }
  const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  const bytes = value => Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(value.length / 4) * 4,"=")), char => char.charCodeAt(0));
  const credentialJSON = credential => ({id: credential.id, rawId: b64(credential.rawId), type: credential.type, response: credential.response.attestationObject ? {clientDataJSON:b64(credential.response.clientDataJSON),attestationObject:b64(credential.response.attestationObject)} : {clientDataJSON:b64(credential.response.clientDataJSON),authenticatorData:b64(credential.response.authenticatorData),signature:b64(credential.response.signature),userHandle:credential.response.userHandle ? b64(credential.response.userHandle) : null}});
  const options = value => { const copy = structuredClone(value); copy.challenge = bytes(copy.challenge); for (const item of (copy.allowCredentials || copy.excludeCredentials || [])) item.id = bytes(item.id); if (copy.user) copy.user.id = bytes(copy.user.id); return copy; };
  const message = () => { error.hidden = false; error.textContent = "Операция не выполнена. Проверьте passkey и попробуйте ещё раз."; };
  const disable = (form, active) => form.querySelectorAll("button,input,select,textarea").forEach(item => { item.disabled = active; });
  const api = async (command, data) => { const response = await fetch("/api", {method:"POST", headers:{"Content-Type":"application/json","X-Sunny-CSRF":root.dataset.csrf}, body:JSON.stringify({command,data}), credentials:"same-origin"}); if (!response.ok) throw new Error("request denied"); return response.json(); };
  const signed = async (operation, payload, passphrase) => { const begin = await api("operation_begin", {operation,payload}); const credential = await navigator.credentials.get({publicKey:options(begin.public_key)}); return api("operation_finish", Object.assign({challenge_id:begin.challenge_id,credential:credentialJSON(credential)}, passphrase ? {passphrase} : {})); };
  const confirmed = (values, field) => !field || values[field] === "yes";
  const legacy = (formData, values) => {
    const action = values.action;
    if (action === "configure") { if (!confirmed(values,"confirm_data_scope")) throw new Error("confirmation"); return ["operation", "configure", {telegram_api_id:values.telegram_api_id,telegram_api_hash:values.telegram_api_hash,vpn_subscription_url:values.vpn_subscription_url,openrouter_api_key:values.openrouter_api_key,openrouter_model:"anthropic/claude-opus-5.5",upload_host:values.upload_host,upload_port:values.upload_port,upload_user:"root",known_host:values.known_host,consent_expires_at:values.consent_expires_at}]; }
    if (action === "select_chats") { if (!confirmed(values,"confirm_lock")) throw new Error("confirmation"); return ["operation", "select_chats", {selection_id:values.selection_id,chat_ids:formData.getAll("chat_id")}]; }
    if (action === "activate_monitoring") { if (!confirmed(values,"confirm_activation")) throw new Error("confirmation"); return ["operation", "activate_monitoring", {}]; }
    if (action === "renew_consent") { if (!confirmed(values,"confirm_renew")) throw new Error("confirmation"); return ["operation", "renew_consent", {value:values.consent_expires_at}]; }
    if (action === "extend_chats") { if (!confirmed(values,"confirm_extend")) throw new Error("confirmation"); return ["operation", "extend_chats", {value:values.extension_message_link}]; }
    if (action === "replace_vpn") { if (!confirmed(values,"confirm_vpn_replace")) throw new Error("confirmation"); return ["operation", "replace_vpn", {value:values.vpn_subscription_url}]; }
    if (action === "reset") { if (!confirmed(values,"confirm_reset")) throw new Error("confirmation"); return ["operation", "revoke_and_reset", {}]; }
    if (action === "ack_manual_revocation") { if (!confirmed(values,"confirm_manual_revocation")) throw new Error("confirmation"); return ["operation", "acknowledge_manual_revocation", {}]; }
    if (action === "send_code") return ["view", "send_code", values.phone];
    if (action === "submit_code") return ["view", "submit_code", values.code];
    if (action === "submit_password") return ["view", "submit_password", values.password];
    if (action === "resolve_chat_links") return ["view", "resolve_chat_links", values.chat_links.split(/\r?\n/).map(value => value.trim()).filter(Boolean)];
    if (action === "set_digest_rich") return ["view", "set_digest_rich", values.rich === "on"];
    if (action === "set_chat_display") return ["view", "set_chat_display", {chat_id:values.chat_id,emoji:values.emoji,kind:values.kind,short_name:values.short_name || null}];
    if (action === "run_now") return ["run", "run_now", {}];
    throw new Error("unknown action");
  };
  const completePasskeyAdd = async (result, name) => { if (!result.registration) return; const credential = await navigator.credentials.create({publicKey:options(result.registration.public_key)}); await api("registration_finish", {challenge_id:result.registration.challenge_id,credential:credentialJSON(credential),name}); };
  const submit = async (form, work) => { const formData = new FormData(form); disable(form,true); try { await work(formData); location.reload(); } catch (_) { message(); } finally { form.reset(); disable(form,false); } };
  document.querySelectorAll("form.secure-operation").forEach(form => form.addEventListener("submit", event => { event.preventDefault(); submit(form, async formData => { const values = Object.fromEntries(formData); const operation = form.dataset.operation; const passphrase = values.passphrase; delete values.passphrase; const payload = operation === "passkey_add" ? {} : (Object.keys(values).length ? values : {}); const result = await signed(operation,payload,passphrase); if (operation === "passkey_add") await completePasskeyAdd(result, values.name); }); }));
  document.querySelectorAll("form:not(.secure-operation):not(#bootstrap-form)").forEach(form => form.addEventListener("submit", event => { event.preventDefault(); submit(form, async formData => { const values = Object.fromEntries(formData); const [kind, action, payload] = legacy(formData, values); if (kind === "operation") await signed(action,payload); else if (kind === "view") await api("view_step", {command:action,value:payload}); else await api("run_now", {}); }); }));
  const bootstrap = document.getElementById("bootstrap-form"); if (bootstrap) bootstrap.addEventListener("submit", event => { event.preventDefault(); submit(bootstrap, async form => { const begin = await api("bootstrap_begin", {token:form.get("bootstrap_token")}); const credential = await navigator.credentials.create({publicKey:options(begin.public_key)}); await api("registration_finish", {challenge_id:begin.challenge_id,credential:credentialJSON(credential),name:form.get("name"),passphrase:form.get("passphrase"),confirm_migration:form.get("confirm_migration") === "yes"}); }); });
})();
