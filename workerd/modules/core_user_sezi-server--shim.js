var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// build/index.js
import { WorkerEntrypoint as yt } from "cloudflare:workers";
import X from "./e10f05167f34a4d4e38063bd896e0d5e800756a0-index_bg.wasm";
var $ = globalThis.__worker_init_state = { criticalError: false, instanceId: 0 };
var E = class {
  static {
    __name(this, "E");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, bt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_containerstartupoptions_free(t, 0);
  }
  get enableInternet() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.__wbg_get_containerstartupoptions_enableInternet(this.__wbg_ptr), t === 16777215 ? void 0 : t !== 0;
  }
  get entrypoint() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let _ = i.__wbindgen_add_to_stack_pointer(-16) >>> 0;
      c(), i.__wbg_get_containerstartupoptions_entrypoint(_, this.__wbg_ptr);
      var t = a().getInt32(_ + 0, true), e = a().getInt32(_ + 4, true), n = lt(t, e);
      return i.__wbindgen_export3(t, e * 4, 4), n;
    } finally {
      i.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get env() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.__wbg_get_containerstartupoptions_env(this.__wbg_ptr), t;
  }
  set enableInternet(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_containerstartupoptions_enableInternet(this.__wbg_ptr, b(t) ? 16777215 : t ? 1 : 0);
  }
  set entrypoint(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e = L(t, i.__wbindgen_export), n = w;
    c(), i.__wbg_set_containerstartupoptions_entrypoint(this.__wbg_ptr, e, n);
  }
  set env(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_containerstartupoptions_env(this.__wbg_ptr, t);
  }
};
Symbol.dispose && (E.prototype[Symbol.dispose] = E.prototype.free);
var P = class {
  static {
    __name(this, "P");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, gt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_intounderlyingbytesource_free(t, 0);
  }
  get autoAllocateChunkSize() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.intounderlyingbytesource_autoAllocateChunkSize(this.__wbg_ptr), t >>> 0;
  }
  cancel() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw();
    c(), i.intounderlyingbytesource_cancel(t);
  }
  pull(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = i.intounderlyingbytesource_pull(this.__wbg_ptr, t), e;
  }
  start(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.intounderlyingbytesource_start(this.__wbg_ptr, t);
  }
  get type() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.intounderlyingbytesource_type(this.__wbg_ptr), ut[t];
  }
};
Symbol.dispose && (P.prototype[Symbol.dispose] = P.prototype.free);
var M = class {
  static {
    __name(this, "M");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, dt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_intounderlyingsink_free(t, 0);
  }
  abort(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e = this.__destroy_into_raw(), n;
    return c(), n = i.intounderlyingsink_abort(e, t), n;
  }
  close() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw(), e;
    return c(), e = i.intounderlyingsink_close(t), e;
  }
  write(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = i.intounderlyingsink_write(this.__wbg_ptr, t), e;
  }
};
Symbol.dispose && (M.prototype[Symbol.dispose] = M.prototype.free);
var O = class r {
  static {
    __name(this, "r");
  }
  static __wrap(t) {
    let e = Object.create(r.prototype);
    return e.__wbg_ptr = t, Object.defineProperty(e, "__wbg_inst", { value: u, writable: true }), H.register(e, { ptr: t, instance: u }, e), e;
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, H.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_intounderlyingsource_free(t, 0);
  }
  cancel() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw();
    c(), i.intounderlyingsource_cancel(t);
  }
  pull(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = i.intounderlyingsource_pull(this.__wbg_ptr, t), e;
  }
};
Symbol.dispose && (O.prototype[Symbol.dispose] = O.prototype.free);
var I = class r2 {
  static {
    __name(this, "r");
  }
  static __wrap(t) {
    let e = Object.create(r2.prototype);
    return e.__wbg_ptr = t, Object.defineProperty(e, "__wbg_inst", { value: u, writable: true }), J.register(e, { ptr: t, instance: u }, e), e;
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, J.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_minifyconfig_free(t, 0);
  }
  get css() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.__wbg_get_minifyconfig_css(this.__wbg_ptr), t !== 0;
  }
  get html() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.__wbg_get_minifyconfig_html(this.__wbg_ptr), t !== 0;
  }
  get js() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.__wbg_get_minifyconfig_js(this.__wbg_ptr), t !== 0;
  }
  set css(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_minifyconfig_css(this.__wbg_ptr, t);
  }
  set html(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_minifyconfig_html(this.__wbg_ptr, t);
  }
  set js(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_minifyconfig_js(this.__wbg_ptr, t);
  }
};
Symbol.dispose && (I.prototype[Symbol.dispose] = I.prototype.free);
var R = class {
  static {
    __name(this, "R");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, K.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_pluginroomlog_free(t, 0);
  }
  alarm() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.pluginroomlog_alarm(this.__wbg_ptr), t;
  }
  connect(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = i.pluginroomlog_connect(this.__wbg_ptr, t), e;
  }
  fetch(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = i.pluginroomlog_fetch(this.__wbg_ptr, t), e;
  }
  constructor(t, e) {
    let n;
    return c(), n = i.pluginroomlog_new(t, e), this.__wbg_ptr = n, Object.defineProperty(this, "__wbg_inst", { value: u, writable: true }), K.register(this, { ptr: n, instance: u }, this), this;
  }
  webSocketClose(t, e, n, _) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let s = +e, f = +_, g = p(n, i.__wbindgen_export, i.__wbindgen_export2), l = w, h;
    return c(), h = i.pluginroomlog_webSocketClose(this.__wbg_ptr, t, s, g, l, f), h;
  }
  webSocketError(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return c(), n = i.pluginroomlog_webSocketError(this.__wbg_ptr, t, e), n;
  }
  webSocketMessage(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return c(), n = i.pluginroomlog_webSocketMessage(this.__wbg_ptr, t, e), n;
  }
};
Symbol.dispose && (R.prototype[Symbol.dispose] = R.prototype.free);
var S = class {
  static {
    __name(this, "S");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, wt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_r2range_free(t, 0);
  }
  get length() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let n = i.__wbindgen_add_to_stack_pointer(-16) >>> 0;
      c(), i.__wbg_get_r2range_length(n, this.__wbg_ptr);
      var t = a().getInt32(n + 0, true), e = a().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      i.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get offset() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let n = i.__wbindgen_add_to_stack_pointer(-16) >>> 0;
      c(), i.__wbg_get_r2range_offset(n, this.__wbg_ptr);
      var t = a().getInt32(n + 0, true), e = a().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      i.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get suffix() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let n = i.__wbindgen_add_to_stack_pointer(-16) >>> 0;
      c(), i.__wbg_get_r2range_suffix(n, this.__wbg_ptr);
      var t = a().getInt32(n + 0, true), e = a().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      i.__wbindgen_add_to_stack_pointer(16);
    }
  }
  set length(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_r2range_length(this.__wbg_ptr, !b(t), b(t) ? 0 : t);
  }
  set offset(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_r2range_offset(this.__wbg_ptr, !b(t), b(t) ? 0 : t);
  }
  set suffix(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), i.__wbg_set_r2range_suffix(this.__wbg_ptr, !b(t), b(t) ? 0 : t);
  }
};
Symbol.dispose && (S.prototype[Symbol.dispose] = S.prototype.free);
var k = class {
  static {
    __name(this, "k");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, G.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), i.__wbg_userinbox_free(t, 0);
  }
  alarm() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = i.userinbox_alarm(this.__wbg_ptr), t;
  }
  connect(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = i.userinbox_connect(this.__wbg_ptr, t), e;
  }
  fetch(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = i.userinbox_fetch(this.__wbg_ptr, t), e;
  }
  constructor(t, e) {
    let n;
    return c(), n = i.userinbox_new(t, e), this.__wbg_ptr = n, Object.defineProperty(this, "__wbg_inst", { value: u, writable: true }), G.register(this, { ptr: n, instance: u }, this), this;
  }
  webSocketClose(t, e, n, _) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let s = +e, f = +_, g = p(n, i.__wbindgen_export, i.__wbindgen_export2), l = w, h;
    return c(), h = i.userinbox_webSocketClose(this.__wbg_ptr, t, s, g, l, f), h;
  }
  webSocketError(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return c(), n = i.userinbox_webSocketError(this.__wbg_ptr, t, e), n;
  }
  webSocketMessage(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return c(), n = i.userinbox_webSocketMessage(this.__wbg_ptr, t, e), n;
  }
};
Symbol.dispose && (k.prototype[Symbol.dispose] = k.prototype.free);
function D() {
  u++, v = null, A = null, typeof numBytesDecoded < "u" && (numBytesDecoded = 0), typeof w < "u" && (w = 0), B = false, q = new WebAssembly.Instance(X, nt()), i = q.exports, i.__wbindgen_start();
}
__name(D, "D");
function Y() {
  let r3;
  return c(), r3 = i.__worker_init_state(), r3;
}
__name(Y, "Y");
function Z(r3, t, e) {
  let n;
  return c(), n = i.fetch(r3, t, e), n;
}
__name(Z, "Z");
function tt(r3, t, e) {
  let n;
  return c(), n = i.scheduled(r3, t, e), n;
}
__name(tt, "tt");
function et() {
  c(), i.start();
}
__name(et, "et");
function nt() {
  return { __proto__: null, "./index_bg.js": { __proto__: null, __wbg_Error_208446807d0d1e30: /* @__PURE__ */ __name(function(t, e) {
    return Error(d(t, e));
  }, "__wbg_Error_208446807d0d1e30"), __wbg_Number_ff192a72a0dcdf6d: /* @__PURE__ */ __name(function(t) {
    return Number(t);
  }, "__wbg_Number_ff192a72a0dcdf6d"), __wbg_String_8564e559799eccda: /* @__PURE__ */ __name(function(t, e) {
    let n = String(e), _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
    a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
  }, "__wbg_String_8564e559799eccda"), __wbg___wbindgen_bigint_get_as_i64_11da4b52cd0aedef: /* @__PURE__ */ __name(function(t, e) {
    let n = e, _ = typeof n == "bigint" ? n : void 0;
    a().setBigInt64((t >>> 0) + 8, b(_) ? BigInt(0) : _, true), a().setInt32((t >>> 0) + 0, !b(_), true);
  }, "__wbg___wbindgen_bigint_get_as_i64_11da4b52cd0aedef"), __wbg___wbindgen_boolean_get_4f1baf9a00be3c74: /* @__PURE__ */ __name(function(t) {
    let e = t, n = typeof e == "boolean" ? e : void 0;
    return b(n) ? 16777215 : n ? 1 : 0;
  }, "__wbg___wbindgen_boolean_get_4f1baf9a00be3c74"), __wbg___wbindgen_debug_string_f249a2a76caa9a55: /* @__PURE__ */ __name(function(t, e) {
    let n = rt(e), _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
    a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
  }, "__wbg___wbindgen_debug_string_f249a2a76caa9a55"), __wbg___wbindgen_in_3f58a9d3b3a7eed2: /* @__PURE__ */ __name(function(t, e) {
    return t in e;
  }, "__wbg___wbindgen_in_3f58a9d3b3a7eed2"), __wbg___wbindgen_is_bigint_5fa10641e039d3ef: /* @__PURE__ */ __name(function(t) {
    return typeof t == "bigint";
  }, "__wbg___wbindgen_is_bigint_5fa10641e039d3ef"), __wbg___wbindgen_is_function_741ff2bb612836f5: /* @__PURE__ */ __name(function(t) {
    return typeof t == "function";
  }, "__wbg___wbindgen_is_function_741ff2bb612836f5"), __wbg___wbindgen_is_null_c22311b1cc228e3a: /* @__PURE__ */ __name(function(t) {
    return t === null;
  }, "__wbg___wbindgen_is_null_c22311b1cc228e3a"), __wbg___wbindgen_is_null_or_undefined_fb96af93c75460ae: /* @__PURE__ */ __name(function(t) {
    return t == null;
  }, "__wbg___wbindgen_is_null_or_undefined_fb96af93c75460ae"), __wbg___wbindgen_is_object_8b968c3ab8e96595: /* @__PURE__ */ __name(function(t) {
    let e = t;
    return typeof e == "object" && e !== null;
  }, "__wbg___wbindgen_is_object_8b968c3ab8e96595"), __wbg___wbindgen_is_string_fc456fee5d3317de: /* @__PURE__ */ __name(function(t) {
    return typeof t == "string";
  }, "__wbg___wbindgen_is_string_fc456fee5d3317de"), __wbg___wbindgen_is_undefined_be5b34249ff1fc15: /* @__PURE__ */ __name(function(t) {
    return t === void 0;
  }, "__wbg___wbindgen_is_undefined_be5b34249ff1fc15"), __wbg___wbindgen_jsval_eq_38d7bfbe4cc84039: /* @__PURE__ */ __name(function(t, e) {
    return t === e;
  }, "__wbg___wbindgen_jsval_eq_38d7bfbe4cc84039"), __wbg___wbindgen_jsval_loose_eq_b2f214e2e4b30e36: /* @__PURE__ */ __name(function(t, e) {
    return t == e;
  }, "__wbg___wbindgen_jsval_loose_eq_b2f214e2e4b30e36"), __wbg___wbindgen_number_get_934b640d0889af78: /* @__PURE__ */ __name(function(t, e) {
    let n = e, _ = typeof n == "number" ? n : void 0;
    a().setFloat64((t >>> 0) + 8, b(_) ? 0 : _, true), a().setInt32((t >>> 0) + 0, !b(_), true);
  }, "__wbg___wbindgen_number_get_934b640d0889af78"), __wbg___wbindgen_reinit_2fe0d0b9c1cc3c21: /* @__PURE__ */ __name(function() {
    B = true;
  }, "__wbg___wbindgen_reinit_2fe0d0b9c1cc3c21"), __wbg___wbindgen_string_get_7ce8eee7fd327545: /* @__PURE__ */ __name(function(t, e) {
    let n = e, _ = typeof n == "string" ? n : void 0;
    var s = b(_) ? 0 : p(_, i.__wbindgen_export, i.__wbindgen_export2), f = w;
    a().setInt32((t >>> 0) + 4, f, true), a().setInt32((t >>> 0) + 0, s, true);
  }, "__wbg___wbindgen_string_get_7ce8eee7fd327545"), __wbg___wbindgen_throw_4c88d8bf264fd984: /* @__PURE__ */ __name(function(t, e) {
    throw new Error(d(t, e));
  }, "__wbg___wbindgen_throw_4c88d8bf264fd984"), __wbg__wbg_cb_unref_09736879a3f67559: /* @__PURE__ */ __name(function(t) {
    t._wbg_cb_unref();
  }, "__wbg__wbg_cb_unref_09736879a3f67559"), __wbg_acceptWebSocket_6893ac0c64b53fb0: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.acceptWebSocket(e);
    }, arguments);
  }, "__wbg_acceptWebSocket_6893ac0c64b53fb0"), __wbg_accept_07989ee561498755: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      t.accept();
    }, arguments);
  }, "__wbg_accept_07989ee561498755"), __wbg_all_d28c206485f72134: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.all();
    }, arguments);
  }, "__wbg_all_d28c206485f72134"), __wbg_append_ba9a4dc30a0323fd: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _, s) {
      t.append(d(e, n), d(_, s));
    }, arguments);
  }, "__wbg_append_ba9a4dc30a0323fd"), __wbg_arrayBuffer_2fd32ecc9ba5d782: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.arrayBuffer();
    }, arguments);
  }, "__wbg_arrayBuffer_2fd32ecc9ba5d782"), __wbg_arrayBuffer_39a766224696fd9d: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.arrayBuffer();
    }, arguments);
  }, "__wbg_arrayBuffer_39a766224696fd9d"), __wbg_batch_d54a0dc86c491bc6: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.batch(e);
    }, arguments);
  }, "__wbg_batch_d54a0dc86c491bc6"), __wbg_bind_0bf8b02f8e144a7d: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.bind(...e);
    }, arguments);
  }, "__wbg_bind_0bf8b02f8e144a7d"), __wbg_bodyUsed_ab7434ab8b017f26: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.bodyUsed;
    }, arguments);
  }, "__wbg_bodyUsed_ab7434ab8b017f26"), __wbg_body_0da01a9a056907d8: /* @__PURE__ */ __name(function(t) {
    let e = t.body;
    return b(e) ? 0 : m(e);
  }, "__wbg_body_0da01a9a056907d8"), __wbg_body_aa8779491c65473d: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.body;
    }, arguments);
  }, "__wbg_body_aa8779491c65473d"), __wbg_buffer_aca05a93c046db1a: /* @__PURE__ */ __name(function(t) {
    return t.buffer;
  }, "__wbg_buffer_aca05a93c046db1a"), __wbg_byobRequest_18280c78e462544c: /* @__PURE__ */ __name(function(t) {
    let e = t.byobRequest;
    return b(e) ? 0 : m(e);
  }, "__wbg_byobRequest_18280c78e462544c"), __wbg_byteLength_c5f3c188d5252e5b: /* @__PURE__ */ __name(function(t) {
    return t.byteLength;
  }, "__wbg_byteLength_c5f3c188d5252e5b"), __wbg_byteOffset_63cdc7b38f33a45e: /* @__PURE__ */ __name(function(t) {
    return t.byteOffset;
  }, "__wbg_byteOffset_63cdc7b38f33a45e"), __wbg_cacheControl_7a6c0db57be93161: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.cacheControl;
      var _ = b(n) ? 0 : p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_cacheControl_7a6c0db57be93161"), __wbg_cacheExpiry_84365f2808afdf06: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      let e = t.cacheExpiry;
      return b(e) ? 0 : m(e);
    }, arguments);
  }, "__wbg_cacheExpiry_84365f2808afdf06"), __wbg_call_275b78b3b6520b92: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _, s) {
      return t.call(e, n, _, s);
    }, arguments);
  }, "__wbg_call_275b78b3b6520b92"), __wbg_call_40b008ba32f73991: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.call(e);
    }, arguments);
  }, "__wbg_call_40b008ba32f73991"), __wbg_call_a410eb4b59ed5965: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return t.call(e, n);
    }, arguments);
  }, "__wbg_call_a410eb4b59ed5965"), __wbg_call_fc92fee6137d452d: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _) {
      return t.call(e, n, _);
    }, arguments);
  }, "__wbg_call_fc92fee6137d452d"), __wbg_cancel_b195250778e9d8e7: /* @__PURE__ */ __name(function(t) {
    return t.cancel();
  }, "__wbg_cancel_b195250778e9d8e7"), __wbg_catch_fd4c7ea14fde9d83: /* @__PURE__ */ __name(function(t, e) {
    return t.catch(e);
  }, "__wbg_catch_fd4c7ea14fde9d83"), __wbg_cause_4cdda1b55a30b227: /* @__PURE__ */ __name(function(t) {
    return t.cause;
  }, "__wbg_cause_4cdda1b55a30b227"), __wbg_cf_3eef96d446a499c0: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      let e = t.cf;
      return b(e) ? 0 : m(e);
    }, arguments);
  }, "__wbg_cf_3eef96d446a499c0"), __wbg_cf_e4bf1d08e9961dec: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      let e = t.cf;
      return b(e) ? 0 : m(e);
    }, arguments);
  }, "__wbg_cf_e4bf1d08e9961dec"), __wbg_clearTimeout_d859c3fbfd863ce7: /* @__PURE__ */ __name(function(t, e) {
    t.clearTimeout(e);
  }, "__wbg_clearTimeout_d859c3fbfd863ce7"), __wbg_close_294d3f727cb7a844: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      t.close();
    }, arguments);
  }, "__wbg_close_294d3f727cb7a844"), __wbg_close_2a8b1ba07b9e0fee: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _) {
      t.close(e, d(n, _));
    }, arguments);
  }, "__wbg_close_2a8b1ba07b9e0fee"), __wbg_close_bf94aa7e38b9a94b: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      t.close();
    }, arguments);
  }, "__wbg_close_bf94aa7e38b9a94b"), __wbg_constructor_76ad3e2c50d259de: /* @__PURE__ */ __name(function(t) {
    return t.constructor;
  }, "__wbg_constructor_76ad3e2c50d259de"), __wbg_contentDisposition_ce793ab7110dfa1f: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.contentDisposition;
      var _ = b(n) ? 0 : p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_contentDisposition_ce793ab7110dfa1f"), __wbg_contentEncoding_550111ff7e6dd405: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.contentEncoding;
      var _ = b(n) ? 0 : p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_contentEncoding_550111ff7e6dd405"), __wbg_contentLanguage_b2f57d341ee434b5: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.contentLanguage;
      var _ = b(n) ? 0 : p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_contentLanguage_b2f57d341ee434b5"), __wbg_contentType_1b59a0112edbe2d5: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.contentType;
      var _ = b(n) ? 0 : p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_contentType_1b59a0112edbe2d5"), __wbg_cron_011257069251b860: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.cron, _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_cron_011257069251b860"), __wbg_crypto_23f565a907d30078: /* @__PURE__ */ __name(function(t) {
    return t.crypto;
  }, "__wbg_crypto_23f565a907d30078"), __wbg_cursor_162b449285ac26fc: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.cursor;
      var _ = b(n) ? 0 : p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_cursor_162b449285ac26fc"), __wbg_deleteAlarm_e03d0e7e46b1af1c: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.deleteAlarm(e);
    }, arguments);
  }, "__wbg_deleteAlarm_e03d0e7e46b1af1c"), __wbg_deleteAll_e9ef46621cab9eee: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.deleteAll();
    }, arguments);
  }, "__wbg_deleteAll_e9ef46621cab9eee"), __wbg_delete_cd0eabf213182785: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      let _, s;
      try {
        return _ = e, s = n, t.delete(d(e, n));
      } finally {
        c(), i.__wbindgen_export3(_, s, 1);
      }
    }, arguments);
  }, "__wbg_delete_cd0eabf213182785"), __wbg_deserializeAttachment_b0638e89b27e2a83: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.deserializeAttachment();
    }, arguments);
  }, "__wbg_deserializeAttachment_b0638e89b27e2a83"), __wbg_done_57e08d0be6e30c02: /* @__PURE__ */ __name(function(t) {
    return t.done;
  }, "__wbg_done_57e08d0be6e30c02"), __wbg_enqueue_c11626eae1c54509: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.enqueue(e);
    }, arguments);
  }, "__wbg_enqueue_c11626eae1c54509"), __wbg_entries_7bb1459bd9b5c2b9: /* @__PURE__ */ __name(function(t) {
    return Object.entries(t);
  }, "__wbg_entries_7bb1459bd9b5c2b9"), __wbg_entries_fb0b3ba27a6e0bf7: /* @__PURE__ */ __name(function(t) {
    return t.entries();
  }, "__wbg_entries_fb0b3ba27a6e0bf7"), __wbg_error_757e9472f8410341: /* @__PURE__ */ __name(function(t, e) {
    let n, _;
    try {
      n = t, _ = e, console.error(d(t, e));
    } finally {
      c(), i.__wbindgen_export3(n, _, 1);
    }
  }, "__wbg_error_757e9472f8410341"), __wbg_error_9b95f63d905893d2: /* @__PURE__ */ __name(function(t, e) {
    console.error(t, e);
  }, "__wbg_error_9b95f63d905893d2"), __wbg_error_d1fc0193610e0e39: /* @__PURE__ */ __name(function(t) {
    console.error(t);
  }, "__wbg_error_d1fc0193610e0e39"), __wbg_exec_85b624bc72d8a6f2: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _) {
      return t.exec(d(e, n), ..._);
    }, arguments);
  }, "__wbg_exec_85b624bc72d8a6f2"), __wbg_fetch_58e62838507dad34: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.fetch(e);
    }, arguments);
  }, "__wbg_fetch_58e62838507dad34"), __wbg_fetch_8991a6a8ea67c83b: /* @__PURE__ */ __name(function(t, e, n, _) {
    return t.fetch(d(e, n), _);
  }, "__wbg_fetch_8991a6a8ea67c83b"), __wbg_fetch_a416b432a33cc077: /* @__PURE__ */ __name(function(t, e, n) {
    return t.fetch(e, n);
  }, "__wbg_fetch_a416b432a33cc077"), __wbg_first_fe3c5a977b563684: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return t.first(e === 0 ? void 0 : d(e, n));
    }, arguments);
  }, "__wbg_first_fe3c5a977b563684"), __wbg_getAlarm_276dab0d75e33652: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.getAlarm(e);
    }, arguments);
  }, "__wbg_getAlarm_276dab0d75e33652"), __wbg_getRandomValues_6b4853624ee06014: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      globalThis.crypto.getRandomValues(x(t, e));
    }, arguments);
  }, "__wbg_getRandomValues_6b4853624ee06014"), __wbg_getRandomValues_8b6f1f663e6f188d: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      globalThis.crypto.getRandomValues(x(t, e));
    }, arguments);
  }, "__wbg_getRandomValues_8b6f1f663e6f188d"), __wbg_getRandomValues_d2908e0b99612b91: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.getRandomValues(e);
    }, arguments);
  }, "__wbg_getRandomValues_d2908e0b99612b91"), __wbg_getReader_3b3096cf504fce5e: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.getReader();
    }, arguments);
  }, "__wbg_getReader_3b3096cf504fce5e"), __wbg_getTime_edc91481cbc4cd78: /* @__PURE__ */ __name(function(t) {
    return t.getTime();
  }, "__wbg_getTime_edc91481cbc4cd78"), __wbg_getWebSocketAutoResponseTimestamp_5567008f751e36e6: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = t.getWebSocketAutoResponseTimestamp(e);
      return b(n) ? 0 : m(n);
    }, arguments);
  }, "__wbg_getWebSocketAutoResponseTimestamp_5567008f751e36e6"), __wbg_getWebSockets_557696c97fc4ec99: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.getWebSockets(), _ = L(n, i.__wbindgen_export), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_getWebSockets_557696c97fc4ec99"), __wbg_get_0ae635d02d232017: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = Reflect.get(t, e);
      return b(n) ? 0 : m(n);
    }, arguments);
  }, "__wbg_get_0ae635d02d232017"), __wbg_get_2080c49015e35254: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return Reflect.get(t, e);
    }, arguments);
  }, "__wbg_get_2080c49015e35254"), __wbg_get_4d87e704eb410caa: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.get(e);
    }, arguments);
  }, "__wbg_get_4d87e704eb410caa"), __wbg_get_556f1c9a5c587e8c: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _) {
      let s = e.get(d(n, _));
      var f = b(s) ? 0 : p(s, i.__wbindgen_export, i.__wbindgen_export2), g = w;
      a().setInt32((t >>> 0) + 4, g, true), a().setInt32((t >>> 0) + 0, f, true);
    }, arguments);
  }, "__wbg_get_556f1c9a5c587e8c"), __wbg_get_5c28e15912dc5a17: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _) {
      let s, f;
      try {
        return s = e, f = n, t.get(d(e, n), _);
      } finally {
        c(), i.__wbindgen_export3(s, f, 1);
      }
    }, arguments);
  }, "__wbg_get_5c28e15912dc5a17"), __wbg_get_635eea311fa1a291: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return Reflect.get(t, e);
    }, arguments);
  }, "__wbg_get_635eea311fa1a291"), __wbg_get_bb8b6b35041e00c9: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return Reflect.get(t, e >>> 0);
    }, arguments);
  }, "__wbg_get_bb8b6b35041e00c9"), __wbg_get_d50e09af39626749: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return t.get(d(e, n));
    }, arguments);
  }, "__wbg_get_d50e09af39626749"), __wbg_get_d7176cfb76d71114: /* @__PURE__ */ __name(function(t, e) {
    return t[e >>> 0];
  }, "__wbg_get_d7176cfb76d71114"), __wbg_get_done_3bf2b4a34e149301: /* @__PURE__ */ __name(function(t) {
    let e = t.done;
    return b(e) ? 16777215 : e ? 1 : 0;
  }, "__wbg_get_done_3bf2b4a34e149301"), __wbg_get_unchecked_e6325ad374eff861: /* @__PURE__ */ __name(function(t, e) {
    return t[e >>> 0];
  }, "__wbg_get_unchecked_e6325ad374eff861"), __wbg_get_value_9454480da7066d61: /* @__PURE__ */ __name(function(t) {
    return t.value;
  }, "__wbg_get_value_9454480da7066d61"), __wbg_get_with_ref_key_fc601247060b7204: /* @__PURE__ */ __name(function(t, e) {
    return t[e];
  }, "__wbg_get_with_ref_key_fc601247060b7204"), __wbg_has_2c4d5cf25ec8c1cf: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return Reflect.has(t, e);
    }, arguments);
  }, "__wbg_has_2c4d5cf25ec8c1cf"), __wbg_headers_5fc0106c076eb731: /* @__PURE__ */ __name(function(t) {
    return t.headers;
  }, "__wbg_headers_5fc0106c076eb731"), __wbg_headers_9ef80dd266706f48: /* @__PURE__ */ __name(function(t) {
    return t.headers;
  }, "__wbg_headers_9ef80dd266706f48"), __wbg_httpMetadata_21af1b769c7da1a5: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.httpMetadata;
    }, arguments);
  }, "__wbg_httpMetadata_21af1b769c7da1a5"), __wbg_idFromName_8e1943d73c953e77: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return t.idFromName(d(e, n));
    }, arguments);
  }, "__wbg_idFromName_8e1943d73c953e77"), __wbg_id_d1861ca6b28d7449: /* @__PURE__ */ __name(function(t, e) {
    let n = e.id, _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
    a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
  }, "__wbg_id_d1861ca6b28d7449"), __wbg_importKey_dffa85a08f1b105a: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _, s, f, g) {
      return t.importKey(d(e, n), _, s, f !== 0, g);
    }, arguments);
  }, "__wbg_importKey_dffa85a08f1b105a"), __wbg_instanceId_65a51bedfd10160a: /* @__PURE__ */ __name(function(t) {
    return t.instanceId;
  }, "__wbg_instanceId_65a51bedfd10160a"), __wbg_instanceof_ArrayBuffer_12cdaa4161423e6b: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = t instanceof ArrayBuffer;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_ArrayBuffer_12cdaa4161423e6b"), __wbg_instanceof_Error_74e3cca0c4a69161: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = t instanceof Error;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Error_74e3cca0c4a69161"), __wbg_instanceof_Map_0b4fc8b62e73f163: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = t instanceof Map;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Map_0b4fc8b62e73f163"), __wbg_instanceof_ReadableStream_ac28304925ec0f96: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = t instanceof ReadableStream;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_ReadableStream_ac28304925ec0f96"), __wbg_instanceof_Response_5b0b4f7f1daeae51: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = t instanceof Response;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Response_5b0b4f7f1daeae51"), __wbg_instanceof_Uint8Array_d7aeb0dcb3108fea: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = t instanceof Uint8Array;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Uint8Array_d7aeb0dcb3108fea"), __wbg_isArray_bcf1376d0d732d08: /* @__PURE__ */ __name(function(t) {
    return Array.isArray(t);
  }, "__wbg_isArray_bcf1376d0d732d08"), __wbg_isSafeInteger_1a35ba4d31e71d38: /* @__PURE__ */ __name(function(t) {
    return Number.isSafeInteger(t);
  }, "__wbg_isSafeInteger_1a35ba4d31e71d38"), __wbg_iterator_e4c5e8f68ada7b58: /* @__PURE__ */ __name(function() {
    return Symbol.iterator;
  }, "__wbg_iterator_e4c5e8f68ada7b58"), __wbg_json_69a74e9055460dab: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.json();
    }, arguments);
  }, "__wbg_json_69a74e9055460dab"), __wbg_key_8f65a2ba15028209: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.key, _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_key_8f65a2ba15028209"), __wbg_keys_296846770c088f87: /* @__PURE__ */ __name(function(t) {
    return t.keys();
  }, "__wbg_keys_296846770c088f87"), __wbg_length_186163212ffe79c3: /* @__PURE__ */ __name(function(t) {
    return t.length;
  }, "__wbg_length_186163212ffe79c3"), __wbg_length_b03a0fabb109b1e9: /* @__PURE__ */ __name(function(t) {
    return t.length;
  }, "__wbg_length_b03a0fabb109b1e9"), __wbg_list_7ac2791e1db606a8: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return t.list(e);
    }, arguments);
  }, "__wbg_list_7ac2791e1db606a8"), __wbg_log_ff86bbb34c295e21: /* @__PURE__ */ __name(function(t) {
    console.log(t);
  }, "__wbg_log_ff86bbb34c295e21"), __wbg_message_43d8c8f1d543a349: /* @__PURE__ */ __name(function(t) {
    return t.message;
  }, "__wbg_message_43d8c8f1d543a349"), __wbg_meta_16ceaf7f888080b3: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.meta;
    }, arguments);
  }, "__wbg_meta_16ceaf7f888080b3"), __wbg_method_3d406ebab4dd9853: /* @__PURE__ */ __name(function(t, e) {
    let n = e.method, _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
    a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
  }, "__wbg_method_3d406ebab4dd9853"), __wbg_minifyconfig_new: /* @__PURE__ */ __name(function(t) {
    return I.__wrap(t);
  }, "__wbg_minifyconfig_new"), __wbg_msCrypto_d5f06fad6bf1409b: /* @__PURE__ */ __name(function(t) {
    return t.msCrypto;
  }, "__wbg_msCrypto_d5f06fad6bf1409b"), __wbg_name_d1fa514fdca6a975: /* @__PURE__ */ __name(function(t) {
    return t.name;
  }, "__wbg_name_d1fa514fdca6a975"), __wbg_name_fd11f69c917c5670: /* @__PURE__ */ __name(function(t) {
    return t.name;
  }, "__wbg_name_fd11f69c917c5670"), __wbg_new_0_36d738a0c8cfac43: /* @__PURE__ */ __name(function() {
    return /* @__PURE__ */ new Date();
  }, "__wbg_new_0_36d738a0c8cfac43"), __wbg_new_0e1d4725a4fe20e1: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _) {
      return new WebSocketRequestResponsePair(d(t, e), d(n, _));
    }, arguments);
  }, "__wbg_new_0e1d4725a4fe20e1"), __wbg_new_0f40481d596956ea: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return new FixedLengthStream(t >>> 0);
    }, arguments);
  }, "__wbg_new_0f40481d596956ea"), __wbg_new_13de428334042d26: /* @__PURE__ */ __name(function(t) {
    return new Uint8Array(t);
  }, "__wbg_new_13de428334042d26"), __wbg_new_277c27c26f94cbc2: /* @__PURE__ */ __name(function() {
    return o(function() {
      return new Headers();
    }, arguments);
  }, "__wbg_new_277c27c26f94cbc2"), __wbg_new_37eb45aaf5eeb820: /* @__PURE__ */ __name(function() {
    return new Array();
  }, "__wbg_new_37eb45aaf5eeb820"), __wbg_new_3e95cd7386bb9a6c: /* @__PURE__ */ __name(function(t) {
    return new Date(t);
  }, "__wbg_new_3e95cd7386bb9a6c"), __wbg_new_7075786089b89c5e: /* @__PURE__ */ __name(function() {
    return /* @__PURE__ */ new Map();
  }, "__wbg_new_7075786089b89c5e"), __wbg_new_787b9fb330d55d78: /* @__PURE__ */ __name(function(t, e) {
    return new Error(d(t, e));
  }, "__wbg_new_787b9fb330d55d78"), __wbg_new_bb74001155cb8ca8: /* @__PURE__ */ __name(function() {
    return new Error();
  }, "__wbg_new_bb74001155cb8ca8"), __wbg_new_big_int_f9fb53cbbcf59d3d: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return new FixedLengthStream(t);
    }, arguments);
  }, "__wbg_new_big_int_f9fb53cbbcf59d3d"), __wbg_new_cd4348290afae586: /* @__PURE__ */ __name(function() {
    return new Object();
  }, "__wbg_new_cd4348290afae586"), __wbg_new_e119023fca43b021: /* @__PURE__ */ __name(function() {
    return o(function() {
      return new WebSocketPair();
    }, arguments);
  }, "__wbg_new_e119023fca43b021"), __wbg_new_from_slice_b8daf545a41c6aa0: /* @__PURE__ */ __name(function(t, e) {
    return new Uint8Array(x(t, e));
  }, "__wbg_new_from_slice_b8daf545a41c6aa0"), __wbg_new_typed_e09da9dae6ee5935: /* @__PURE__ */ __name(function(t, e) {
    try {
      var n = { a: t, b: e }, _ = /* @__PURE__ */ __name((f, g) => {
        let l = n.a;
        n.a = 0;
        try {
          return st(l, n.b, f, g);
        } finally {
          n.a = l;
        }
      }, "_");
      return new Promise(_);
    } finally {
      n.a = 0;
    }
  }, "__wbg_new_typed_e09da9dae6ee5935"), __wbg_new_with_byte_offset_and_length_3cd32055a417f095: /* @__PURE__ */ __name(function(t, e, n) {
    return new Uint8Array(t, e >>> 0, n >>> 0);
  }, "__wbg_new_with_byte_offset_and_length_3cd32055a417f095"), __wbg_new_with_headers_28412d4f955f6225: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return new Headers(t);
    }, arguments);
  }, "__wbg_new_with_headers_28412d4f955f6225"), __wbg_new_with_into_underlying_source_ba3944e7f4c9d0c3: /* @__PURE__ */ __name(function(t, e) {
    return new ReadableStream(O.__wrap(t), e);
  }, "__wbg_new_with_into_underlying_source_ba3944e7f4c9d0c3"), __wbg_new_with_length_01b143a7e5dd5a3e: /* @__PURE__ */ __name(function(t) {
    return new Uint8Array(t >>> 0);
  }, "__wbg_new_with_length_01b143a7e5dd5a3e"), __wbg_new_with_opt_buffer_source_and_init_efb63b64b37a12c7: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return new Response(t, e);
    }, arguments);
  }, "__wbg_new_with_opt_buffer_source_and_init_efb63b64b37a12c7"), __wbg_new_with_opt_readable_stream_and_init_383c64eccf9e9cc7: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      return new Response(t, e);
    }, arguments);
  }, "__wbg_new_with_opt_readable_stream_and_init_383c64eccf9e9cc7"), __wbg_new_with_opt_str_and_init_6456bed24baae6fc: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return new Response(t === 0 ? void 0 : d(t, e), n);
    }, arguments);
  }, "__wbg_new_with_opt_str_and_init_6456bed24baae6fc"), __wbg_new_with_request_c816ddec918d6719: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return new Request(t);
    }, arguments);
  }, "__wbg_new_with_request_c816ddec918d6719"), __wbg_new_with_str_and_init_d9f6b5611184e16b: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return new Request(d(t, e), n);
    }, arguments);
  }, "__wbg_new_with_str_and_init_d9f6b5611184e16b"), __wbg_next_178c1651c11432b3: /* @__PURE__ */ __name(function(t) {
    return t.next;
  }, "__wbg_next_178c1651c11432b3"), __wbg_next_af5ac6a08bb0a717: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.next();
    }, arguments);
  }, "__wbg_next_af5ac6a08bb0a717"), __wbg_node_86166ff8ce1f2002: /* @__PURE__ */ __name(function(t) {
    return t.node;
  }, "__wbg_node_86166ff8ce1f2002"), __wbg_objects_8ea218877f02e1ed: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      let n = e.objects, _ = L(n, i.__wbindgen_export), s = w;
      a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
    }, arguments);
  }, "__wbg_objects_8ea218877f02e1ed"), __wbg_of_027eb15371aac932: /* @__PURE__ */ __name(function(t) {
    return Array.of(t);
  }, "__wbg_of_027eb15371aac932"), __wbg_pipeTo_a955693c847d79e3: /* @__PURE__ */ __name(function(t, e) {
    return t.pipeTo(e);
  }, "__wbg_pipeTo_a955693c847d79e3"), __wbg_prepare_50d1ec53a3871b75: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return t.prepare(d(e, n));
    }, arguments);
  }, "__wbg_prepare_50d1ec53a3871b75"), __wbg_process_91f425a63f58e399: /* @__PURE__ */ __name(function(t) {
    return t.process;
  }, "__wbg_process_91f425a63f58e399"), __wbg_prototypesetcall_13162965d1fe7aa3: /* @__PURE__ */ __name(function(t, e, n) {
    Uint8Array.prototype.set.call(x(t, e), n);
  }, "__wbg_prototypesetcall_13162965d1fe7aa3"), __wbg_push_c9f4893fc209f768: /* @__PURE__ */ __name(function(t, e) {
    return t.push(e);
  }, "__wbg_push_c9f4893fc209f768"), __wbg_put_71e6bd12597a13aa: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _, s) {
      let f, g;
      try {
        return f = e, g = n, t.put(d(e, n), _, s);
      } finally {
        c(), i.__wbindgen_export3(f, g, 1);
      }
    }, arguments);
  }, "__wbg_put_71e6bd12597a13aa"), __wbg_put_e23699e64023d941: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _) {
      return t.put(d(e, n), _);
    }, arguments);
  }, "__wbg_put_e23699e64023d941"), __wbg_queueMicrotask_1e8503a8a690f0a3: /* @__PURE__ */ __name(function(t) {
    return t.queueMicrotask;
  }, "__wbg_queueMicrotask_1e8503a8a690f0a3"), __wbg_queueMicrotask_4a1a4d8dd332373b: /* @__PURE__ */ __name(function(t) {
    queueMicrotask(t);
  }, "__wbg_queueMicrotask_4a1a4d8dd332373b"), __wbg_randomFillSync_34b023059e3363de: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.randomFillSync(e);
    }, arguments);
  }, "__wbg_randomFillSync_34b023059e3363de"), __wbg_read_e3bea75dace70752: /* @__PURE__ */ __name(function(t) {
    return t.read();
  }, "__wbg_read_e3bea75dace70752"), __wbg_readable_11d72b62fcfdd1ec: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.readable;
    }, arguments);
  }, "__wbg_readable_11d72b62fcfdd1ec"), __wbg_readable_e49a1e3aca2bf0e0: /* @__PURE__ */ __name(function(t) {
    return t.readable;
  }, "__wbg_readable_e49a1e3aca2bf0e0"), __wbg_releaseLock_eddf1401c763f0b9: /* @__PURE__ */ __name(function(t) {
    t.releaseLock();
  }, "__wbg_releaseLock_eddf1401c763f0b9"), __wbg_require_9a7d8cc2e1d275c0: /* @__PURE__ */ __name(function() {
    return o(function() {
      return module.require;
    }, arguments);
  }, "__wbg_require_9a7d8cc2e1d275c0"), __wbg_resolve_dbf78ab4942478b0: /* @__PURE__ */ __name(function(t) {
    return Promise.resolve(t);
  }, "__wbg_resolve_dbf78ab4942478b0"), __wbg_respond_d97c023ee981d1f5: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.respond(e >>> 0);
    }, arguments);
  }, "__wbg_respond_d97c023ee981d1f5"), __wbg_results_978a5156e9f5bf3d: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      let e = t.results;
      return b(e) ? 0 : m(e);
    }, arguments);
  }, "__wbg_results_978a5156e9f5bf3d"), __wbg_run_ba372e9d0b56e06f: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.run();
    }, arguments);
  }, "__wbg_run_ba372e9d0b56e06f"), __wbg_scheduledTime_db16f6f6692a082d: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.scheduledTime;
    }, arguments);
  }, "__wbg_scheduledTime_db16f6f6692a082d"), __wbg_send_cd51063ca1be4d0f: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      t.send(d(e, n));
    }, arguments);
  }, "__wbg_send_cd51063ca1be4d0f"), __wbg_serializeAttachment_b3838d362dd24b64: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.serializeAttachment(e);
    }, arguments);
  }, "__wbg_serializeAttachment_b3838d362dd24b64"), __wbg_setAlarm_039d09296f34bacd: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return t.setAlarm(e, n);
    }, arguments);
  }, "__wbg_setAlarm_039d09296f34bacd"), __wbg_setTimeout_7b54aa5f72cd7066: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return t.setTimeout(e, n);
    }, arguments);
  }, "__wbg_setTimeout_7b54aa5f72cd7066"), __wbg_setWebSocketAutoResponse_0ddde035f38bfe21: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.setWebSocketAutoResponse(e);
    }, arguments);
  }, "__wbg_setWebSocketAutoResponse_0ddde035f38bfe21"), __wbg_set_2793479888329cb6: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n) {
      return Reflect.set(t, e, n);
    }, arguments);
  }, "__wbg_set_2793479888329cb6"), __wbg_set_8282f7e0d2d01336: /* @__PURE__ */ __name(function(t, e, n) {
    return t.set(e, n);
  }, "__wbg_set_8282f7e0d2d01336"), __wbg_set_bcb0ec2400cfa22e: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _, s) {
      t.set(d(e, n), d(_, s));
    }, arguments);
  }, "__wbg_set_bcb0ec2400cfa22e"), __wbg_set_body_877d5251e78ca815: /* @__PURE__ */ __name(function(t, e) {
    t.body = e;
  }, "__wbg_set_body_877d5251e78ca815"), __wbg_set_cache_7a23201e29cbd632: /* @__PURE__ */ __name(function(t, e) {
    t.cache = at[e];
  }, "__wbg_set_cache_7a23201e29cbd632"), __wbg_set_criticalError_c30445da7038dbf2: /* @__PURE__ */ __name(function(t, e) {
    t.criticalError = e !== 0;
  }, "__wbg_set_criticalError_c30445da7038dbf2"), __wbg_set_d2d33b52458e984a: /* @__PURE__ */ __name(function(t, e, n) {
    t[e >>> 0] = n;
  }, "__wbg_set_d2d33b52458e984a"), __wbg_set_e4b9a833d288759a: /* @__PURE__ */ __name(function(t, e, n) {
    t[e] = n;
  }, "__wbg_set_e4b9a833d288759a"), __wbg_set_feb3714f475485ba: /* @__PURE__ */ __name(function(t, e, n) {
    t.set(x(e, n));
  }, "__wbg_set_feb3714f475485ba"), __wbg_set_headers_07f10dbe49bc0e77: /* @__PURE__ */ __name(function(t, e) {
    t.headers = e;
  }, "__wbg_set_headers_07f10dbe49bc0e77"), __wbg_set_headers_6d75a7df4eb22716: /* @__PURE__ */ __name(function(t, e) {
    t.headers = e;
  }, "__wbg_set_headers_6d75a7df4eb22716"), __wbg_set_high_water_mark_2c2355a75a627679: /* @__PURE__ */ __name(function(t, e) {
    t.highWaterMark = e;
  }, "__wbg_set_high_water_mark_2c2355a75a627679"), __wbg_set_instanceId_6f5f77d81e249b49: /* @__PURE__ */ __name(function(t, e) {
    t.instanceId = e >>> 0;
  }, "__wbg_set_instanceId_6f5f77d81e249b49"), __wbg_set_method_639e69af35614d36: /* @__PURE__ */ __name(function(t, e, n) {
    t.method = d(e, n);
  }, "__wbg_set_method_639e69af35614d36"), __wbg_set_redirect_a95a432ab7d10765: /* @__PURE__ */ __name(function(t, e) {
    t.redirect = ft[e];
  }, "__wbg_set_redirect_a95a432ab7d10765"), __wbg_set_signal_0b2eee78907e5ba7: /* @__PURE__ */ __name(function(t, e) {
    t.signal = e;
  }, "__wbg_set_signal_0b2eee78907e5ba7"), __wbg_set_status_bd9dc81d1c17b108: /* @__PURE__ */ __name(function(t, e) {
    t.status = e;
  }, "__wbg_set_status_bd9dc81d1c17b108"), __wbg_sign_2249f944ab66a363: /* @__PURE__ */ __name(function() {
    return o(function(t, e, n, _, s, f) {
      return t.sign(d(e, n), _, x(s, f));
    }, arguments);
  }, "__wbg_sign_2249f944ab66a363"), __wbg_size_d6b35c1ab8137a7f: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.size;
    }, arguments);
  }, "__wbg_size_d6b35c1ab8137a7f"), __wbg_sql_cabda3440c70072f: /* @__PURE__ */ __name(function(t) {
    return t.sql;
  }, "__wbg_sql_cabda3440c70072f"), __wbg_stack_575c4e0918581b9c: /* @__PURE__ */ __name(function(t, e) {
    let n = e.stack, _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
    a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
  }, "__wbg_stack_575c4e0918581b9c"), __wbg_static_accessor_GLOBAL_THIS_003ee833af9699fc: /* @__PURE__ */ __name(function() {
    let t = typeof globalThis > "u" ? void 0 : globalThis;
    return b(t) ? 0 : m(t);
  }, "__wbg_static_accessor_GLOBAL_THIS_003ee833af9699fc"), __wbg_static_accessor_GLOBAL_e4293fb22cbe77da: /* @__PURE__ */ __name(function() {
    let t = typeof global > "u" ? void 0 : global;
    return b(t) ? 0 : m(t);
  }, "__wbg_static_accessor_GLOBAL_e4293fb22cbe77da"), __wbg_static_accessor_INIT_STATE_b2269150d11f01e0: /* @__PURE__ */ __name(function() {
    return $;
  }, "__wbg_static_accessor_INIT_STATE_b2269150d11f01e0"), __wbg_static_accessor_SELF_53bb20457401453d: /* @__PURE__ */ __name(function() {
    let t = typeof self > "u" ? void 0 : self;
    return b(t) ? 0 : m(t);
  }, "__wbg_static_accessor_SELF_53bb20457401453d"), __wbg_static_accessor_WINDOW_b5e0810bfecb7feb: /* @__PURE__ */ __name(function() {
    let t = typeof window > "u" ? void 0 : window;
    return b(t) ? 0 : m(t);
  }, "__wbg_static_accessor_WINDOW_b5e0810bfecb7feb"), __wbg_status_cb85b6c8d1769fa1: /* @__PURE__ */ __name(function(t) {
    return t.status;
  }, "__wbg_status_cb85b6c8d1769fa1"), __wbg_storage_00d86055b2dc3100: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.storage;
    }, arguments);
  }, "__wbg_storage_00d86055b2dc3100"), __wbg_stringify_0a0fbf2ef722380a: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return JSON.stringify(t);
    }, arguments);
  }, "__wbg_stringify_0a0fbf2ef722380a"), __wbg_subarray_58f388a9247ac0bb: /* @__PURE__ */ __name(function(t, e, n) {
    return t.subarray(e >>> 0, n >>> 0);
  }, "__wbg_subarray_58f388a9247ac0bb"), __wbg_text_2d9a65a87b992bc0: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.text();
    }, arguments);
  }, "__wbg_text_2d9a65a87b992bc0"), __wbg_then_656f253a5dd7d8ea: /* @__PURE__ */ __name(function(t, e, n) {
    return t.then(e, n);
  }, "__wbg_then_656f253a5dd7d8ea"), __wbg_then_e3f7f2d365708be8: /* @__PURE__ */ __name(function(t, e) {
    return t.then(e);
  }, "__wbg_then_e3f7f2d365708be8"), __wbg_toArray_2757e80d5ccf01a6: /* @__PURE__ */ __name(function(t) {
    return t.toArray();
  }, "__wbg_toArray_2757e80d5ccf01a6"), __wbg_toISOString_51ebc75332aba76a: /* @__PURE__ */ __name(function(t) {
    return t.toISOString();
  }, "__wbg_toISOString_51ebc75332aba76a"), __wbg_truncated_9ac62c12dff19018: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.truncated;
    }, arguments);
  }, "__wbg_truncated_9ac62c12dff19018"), __wbg_url_1be993c7b186415b: /* @__PURE__ */ __name(function(t, e) {
    let n = e.url, _ = p(n, i.__wbindgen_export, i.__wbindgen_export2), s = w;
    a().setInt32((t >>> 0) + 4, s, true), a().setInt32((t >>> 0) + 0, _, true);
  }, "__wbg_url_1be993c7b186415b"), __wbg_value_e0f328965e184931: /* @__PURE__ */ __name(function(t) {
    return t.value;
  }, "__wbg_value_e0f328965e184931"), __wbg_versions_6e128a981b0df859: /* @__PURE__ */ __name(function(t) {
    return t.versions;
  }, "__wbg_versions_6e128a981b0df859"), __wbg_view_3b708d3bdaf3fc96: /* @__PURE__ */ __name(function(t) {
    let e = t.view;
    return b(e) ? 0 : m(e);
  }, "__wbg_view_3b708d3bdaf3fc96"), __wbg_waitUntil_0c139a1768f7d284: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.waitUntil(e);
    }, arguments);
  }, "__wbg_waitUntil_0c139a1768f7d284"), __wbg_waitUntil_fdcf8bf2aef09039: /* @__PURE__ */ __name(function() {
    return o(function(t, e) {
      t.waitUntil(e);
    }, arguments);
  }, "__wbg_waitUntil_fdcf8bf2aef09039"), __wbg_warn_228ff2257384d295: /* @__PURE__ */ __name(function(t) {
    console.warn(t);
  }, "__wbg_warn_228ff2257384d295"), __wbg_webSocket_71791e807603b1e4: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      let e = t.webSocket;
      return b(e) ? 0 : m(e);
    }, arguments);
  }, "__wbg_webSocket_71791e807603b1e4"), __wbg_writable_1924ab50750acb0f: /* @__PURE__ */ __name(function() {
    return o(function(t) {
      return t.writable;
    }, arguments);
  }, "__wbg_writable_1924ab50750acb0f"), __wbg_writable_9e4740dc4a808f89: /* @__PURE__ */ __name(function(t) {
    return t.writable;
  }, "__wbg_writable_9e4740dc4a808f89"), __wbindgen_generic_0000000000000001: /* @__PURE__ */ __name(function(t, e) {
    return C(t, e, ot);
  }, "__wbindgen_generic_0000000000000001"), __wbindgen_generic_0000000000000002: /* @__PURE__ */ __name(function(t, e) {
    return C(t, e, ct);
  }, "__wbindgen_generic_0000000000000002"), __wbindgen_generic_0000000000000003: /* @__PURE__ */ __name(function(t, e) {
    return C(t, e, it);
  }, "__wbindgen_generic_0000000000000003"), __wbindgen_generic_0000000000000004: /* @__PURE__ */ __name(function(t) {
    return t;
  }, "__wbindgen_generic_0000000000000004"), __wbindgen_generic_0000000000000005: /* @__PURE__ */ __name(function(t) {
    return t;
  }, "__wbindgen_generic_0000000000000005"), __wbindgen_generic_0000000000000006: /* @__PURE__ */ __name(function(t, e) {
    return x(t, e);
  }, "__wbindgen_generic_0000000000000006"), __wbindgen_generic_0000000000000007: /* @__PURE__ */ __name(function(t, e) {
    return d(t, e);
  }, "__wbindgen_generic_0000000000000007"), __wbindgen_generic_0000000000000008: /* @__PURE__ */ __name(function(t) {
    return BigInt.asUintN(64, t);
  }, "__wbindgen_generic_0000000000000008"), __wbindgen_init_externref_table: /* @__PURE__ */ __name(function() {
    let t = i.__wbindgen_externrefs;
    t.set(0, void 0), t.set(1024, void 0), t.set(1025, null), t.set(1026, true), t.set(1027, false);
  }, "__wbindgen_init_externref_table") } };
}
__name(nt, "nt");
function c() {
  if (B) {
    D();
    return;
  }
}
__name(c, "c");
function it(r3, t) {
  c(), i.__wasm_bindgen_func_elem_8360(r3, t);
}
__name(it, "it");
function ot(r3, t, e) {
  c(), i.__wasm_bindgen_func_elem_7805(r3, t, e);
}
__name(ot, "ot");
function st(r3, t, e, n) {
  c(), i.__wasm_bindgen_func_elem_4122(r3, t, e, n);
}
__name(st, "st");
function ct(r3, t, e) {
  try {
    let s = i.__wbindgen_add_to_stack_pointer(-16) >>> 0;
    c(), i.__wasm_bindgen_func_elem_4068(s, r3, t, e);
    var n = a().getInt32(s + 0, true), _ = a().getInt32(s + 4, true);
    if (_) throw pt(n);
  } finally {
    i.__wbindgen_add_to_stack_pointer(16);
  }
}
__name(ct, "ct");
var ut = ["bytes"];
var at = ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"];
var ft = ["follow", "error", "manual"];
var u = 0;
var bt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_containerstartupoptions_free(r3, 1);
});
var gt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_intounderlyingbytesource_free(r3, 1);
});
var dt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_intounderlyingsink_free(r3, 1);
});
var H = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_intounderlyingsource_free(r3, 1);
});
var J = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_minifyconfig_free(r3, 1);
});
var K = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_pluginroomlog_free(r3, 1);
});
var wt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_r2range_free(r3, 1);
});
var G = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: r3, instance: t }) => {
  t === u && i.__wbg_userinbox_free(r3, 1);
});
function m(r3) {
  let t = i.__wbindgen_export5();
  return i.__wbindgen_externrefs.set(t, r3), t;
}
__name(m, "m");
var Q = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry((r3) => {
  r3.instance === u && i.__wbindgen_export7(r3.a, r3.b);
});
function rt(r3) {
  switch (typeof r3) {
    case "number":
    case "boolean":
    case "undefined":
      return `${r3}`;
    case "string":
      return JSON.stringify(r3);
    case "bigint":
      return `${r3}n`;
    case "symbol":
      return r3.description !== void 0 ? `Symbol(${r3.description})` : "Symbol";
    case "function":
      return typeof r3.name == "string" && r3.name !== "" ? `Function(${r3.name})` : "Function";
    case "object": {
      if (r3 === null) return "null";
      if (Array.isArray(r3)) return "[" + Array.from(r3, rt).join(", ") + "]";
      if (r3 instanceof Error) return `${r3.name}: ${r3.message}
${r3.stack}`;
      let t = toString.call(r3), e = /\[object ([^\]]+)\]/.exec(t)?.[1];
      if (e === void 0) return t;
      if (e === "Object") try {
        return "Object(" + JSON.stringify(r3) + ")";
      } catch {
        return "Object";
      }
      return e;
    }
  }
}
__name(rt, "rt");
function lt(r3, t) {
  r3 = r3 >>> 0;
  let e = a(), n = [];
  for (let _ = r3; _ < r3 + 4 * t; _ += 4) n.push(i.__wbindgen_externrefs.get(e.getUint32(_, true)));
  return i.__wbindgen_export6(r3, t), n;
}
__name(lt, "lt");
function x(r3, t) {
  return r3 = r3 >>> 0, T().subarray(r3 / 1, r3 / 1 + t);
}
__name(x, "x");
var v = null;
function a() {
  return (v === null || v.buffer.detached === true || v.buffer.detached === void 0 && v.buffer !== i.memory.buffer) && (v = new DataView(i.memory.buffer)), v;
}
__name(a, "a");
function d(r3, t) {
  return r3 = r3 >>> 0, mt(T().subarray(r3, r3 + t));
}
__name(d, "d");
var A = null;
function T() {
  return (A === null || A.byteLength === 0) && (A = new Uint8Array(i.memory.buffer)), A;
}
__name(T, "T");
function o(r3, t) {
  try {
    return r3.apply(this, t);
  } catch (e) {
    let n = m(e);
    i.__wbindgen_export4(n);
  }
}
__name(o, "o");
function b(r3) {
  return r3 == null;
}
__name(b, "b");
function C(r3, t, e) {
  let n = { a: r3, b: t, cnt: 1, instance: u }, _ = /* @__PURE__ */ __name((...s) => {
    if (n.instance !== u) throw new Error("Cannot invoke closure from previous WASM instance");
    n.cnt++;
    let f = n.a;
    n.a = 0;
    try {
      return e(f, n.b, ...s);
    } finally {
      n.a = f, _._wbg_cb_unref();
    }
  }, "_");
  return _._wbg_cb_unref = () => {
    --n.cnt === 0 && (i.__wbindgen_export7(n.a, n.b), n.a = 0, Q.unregister(n));
  }, Q.register(_, n, n), _;
}
__name(C, "C");
function L(r3, t) {
  let e = t(r3.length * 4, 4) >>> 0;
  for (let n = 0; n < r3.length; n++) {
    let _ = m(r3[n]);
    a().setUint32(e + 4 * n, _, true);
  }
  return w = r3.length, e;
}
__name(L, "L");
function p(r3, t, e) {
  if (e === void 0) {
    let g = z.encode(r3), l = t(g.length, 1) >>> 0;
    return T().subarray(l, l + g.length).set(g), w = g.length, l;
  }
  let n = r3.length, _ = t(n, 1) >>> 0, s = T(), f = 0;
  for (; f < n; f++) {
    let g = r3.charCodeAt(f);
    if (g > 127) break;
    s[_ + f] = g;
  }
  if (f !== n) {
    f !== 0 && (r3 = r3.slice(f)), _ = e(_, n, n = f + r3.length * 3, 1) >>> 0;
    let g = T().subarray(_ + f, _ + n), l = z.encodeInto(r3, g);
    f += l.written, _ = e(_, n, f, 1) >>> 0;
  }
  return w = f, _;
}
__name(p, "p");
var B = false;
function pt(r3) {
  let t = i.__wbindgen_externrefs.get(r3);
  return i.__wbindgen_export8(r3), t;
}
__name(pt, "pt");
var _t = new TextDecoder("utf-8", { ignoreBOM: true });
_t.decode();
function mt(r3) {
  return _t.decode(r3);
}
__name(mt, "mt");
var z = new TextEncoder();
"encodeInto" in z || (z.encodeInto = function(r3, t) {
  let e = z.encode(r3);
  return t.set(e), { read: r3.length, written: e.length };
});
var w = 0;
var q = new WebAssembly.Instance(X, nt());
var i = q.exports;
i.__wbindgen_start();
Error.stackTraceLimit = 100;
var y = Y();
function N() {
  y.criticalError && (console.log("Reinitializing Wasm application"), D(), y.criticalError = false, y.instanceId++);
}
__name(N, "N");
addEventListener("error", (r3) => {
  V(r3.error);
});
function V(r3) {
  r3 instanceof WebAssembly.RuntimeError && (console.error("Critical", r3), y.criticalError = true);
}
__name(V, "V");
var j = class extends yt {
  static {
    __name(this, "j");
  }
};
j.prototype.fetch = function(t) {
  return Z.call(this, t, this.env, this.ctx);
};
j.prototype.scheduled = function(t) {
  return tt.call(this, t, this.env, this.ctx);
};
j.prototype.start = et;
var xt = { set: /* @__PURE__ */ __name((r3, t, e, n) => Reflect.set(r3.instance, t, e, n), "set"), has: /* @__PURE__ */ __name((r3, t) => Reflect.has(r3.instance, t), "has"), deleteProperty: /* @__PURE__ */ __name((r3, t) => Reflect.deleteProperty(r3.instance, t), "deleteProperty"), apply: /* @__PURE__ */ __name((r3, t, e) => Reflect.apply(r3.instance, t, e), "apply"), construct: /* @__PURE__ */ __name((r3, t, e) => Reflect.construct(r3.instance, t, e), "construct"), getPrototypeOf: /* @__PURE__ */ __name((r3) => Reflect.getPrototypeOf(r3.instance), "getPrototypeOf"), setPrototypeOf: /* @__PURE__ */ __name((r3, t) => Reflect.setPrototypeOf(r3.instance, t), "setPrototypeOf"), isExtensible: /* @__PURE__ */ __name((r3) => Reflect.isExtensible(r3.instance), "isExtensible"), preventExtensions: /* @__PURE__ */ __name((r3) => Reflect.preventExtensions(r3.instance), "preventExtensions"), getOwnPropertyDescriptor: /* @__PURE__ */ __name((r3, t) => Reflect.getOwnPropertyDescriptor(r3.instance, t), "getOwnPropertyDescriptor"), defineProperty: /* @__PURE__ */ __name((r3, t, e) => Reflect.defineProperty(r3.instance, t, e), "defineProperty"), ownKeys: /* @__PURE__ */ __name((r3) => Reflect.ownKeys(r3.instance), "ownKeys") };
var F = { construct(r3, t, e) {
  try {
    N();
    let n = { instance: Reflect.construct(r3, t, e), instanceId: y.instanceId, ctor: r3, args: t, newTarget: e };
    return new Proxy(n, { ...xt, get(_, s, f) {
      _.instanceId !== y.instanceId && (_.instance = Reflect.construct(_.ctor, _.args, _.newTarget), _.instanceId = y.instanceId);
      let g = Reflect.get(_.instance, s, f);
      return typeof g != "function" ? g : g.constructor === Function ? new Proxy(g, { apply(l, h, U) {
        N();
        try {
          return l.apply(h, U);
        } catch (W) {
          throw V(W), W;
        }
      } }) : new Proxy(g, { async apply(l, h, U) {
        N();
        try {
          return await l.apply(h, U);
        } catch (W) {
          throw V(W), W;
        }
      } });
    } });
  } catch (n) {
    throw y.criticalError = true, n;
  }
} };
var St = new Proxy(j, F);
var kt = new Proxy(E, F);
var jt = new Proxy(I, F);
var Ft = new Proxy(R, F);
var Wt = new Proxy(S, F);
var At = new Proxy(k, F);

// ../../../../Projeler/sezi-server/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../../../Projeler/sezi-server/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-Nb5CbH/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = St;

// ../../../../Projeler/sezi-server/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-Nb5CbH/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  kt as ContainerStartupOptions,
  jt as MinifyConfig,
  Ft as PluginRoomLog,
  Wt as R2Range,
  At as UserInbox,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=shim.js.map

//# sourceURL=file:///home/hasan/.cache/gecici/sezi-workerd.SsxhsF/relay/.wrangler/tmp/dev-GiOlkV/shim.js