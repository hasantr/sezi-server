var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// build/index.js
import { WorkerEntrypoint as Et } from "cloudflare:workers";
import et from "./334e0b270f335596dc31cb6f31b27ee414aadb34-index_bg.wasm";
var K = globalThis.__worker_init_state = { criticalError: false, instanceId: 0 };
var W = class {
  static {
    __name(this, "W");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, pt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_containerstartupoptions_free(t, 0);
  }
  get enableInternet() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.__wbg_get_containerstartupoptions_enableInternet(this.__wbg_ptr), t === 16777215 ? void 0 : t !== 0;
  }
  get entrypoint() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
      let o = s.__wbindgen_add_to_stack_pointer(-16);
      a(), s.__wbg_get_containerstartupoptions_entrypoint(o, this.__wbg_ptr);
      var t = b().getInt32(o + 0, true), e = b().getInt32(o + 4, true), n = It(t, e).slice();
      return s.__wbindgen_export4(t, e * 4, 4), n;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get env() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.__wbg_get_containerstartupoptions_env(this.__wbg_ptr), d(t);
  }
  set enableInternet(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_containerstartupoptions_enableInternet(this.__wbg_ptr, w(t) ? 16777215 : t ? 1 : 0);
  }
  set entrypoint(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let e = V(t, s.__wbindgen_export), n = h;
    a(), s.__wbg_set_containerstartupoptions_entrypoint(this.__wbg_ptr, e, n);
  }
  set env(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_containerstartupoptions_env(this.__wbg_ptr, _(t));
  }
};
Symbol.dispose && (W.prototype[Symbol.dispose] = W.prototype.free);
var A = class {
  static {
    __name(this, "A");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, ht.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_intounderlyingbytesource_free(t, 0);
  }
  get autoAllocateChunkSize() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.intounderlyingbytesource_autoAllocateChunkSize(this.__wbg_ptr), t >>> 0;
  }
  cancel() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw();
    a(), s.intounderlyingbytesource_cancel(t);
  }
  pull(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return a(), e = s.intounderlyingbytesource_pull(this.__wbg_ptr, _(t)), d(e);
  }
  start(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.intounderlyingbytesource_start(this.__wbg_ptr, _(t));
  }
  get type() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.intounderlyingbytesource_type(this.__wbg_ptr), dt[t];
  }
};
Symbol.dispose && (A.prototype[Symbol.dispose] = A.prototype.free);
var z = class {
  static {
    __name(this, "z");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, mt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_intounderlyingsink_free(t, 0);
  }
  abort(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let e = this.__destroy_into_raw(), n;
    return a(), n = s.intounderlyingsink_abort(e, _(t)), d(n);
  }
  close() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw(), e;
    return a(), e = s.intounderlyingsink_close(t), d(e);
  }
  write(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return a(), e = s.intounderlyingsink_write(this.__wbg_ptr, _(t)), d(e);
  }
};
Symbol.dispose && (z.prototype[Symbol.dispose] = z.prototype.free);
var j = class i {
  static {
    __name(this, "i");
  }
  static __wrap(t) {
    let e = Object.create(i.prototype);
    return e.__wbg_ptr = t, Object.defineProperty(e, "__wbg_inst", { value: f, writable: true }), Q.register(e, { ptr: t, instance: f }, e), e;
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, Q.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_intounderlyingsource_free(t, 0);
  }
  cancel() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw();
    a(), s.intounderlyingsource_cancel(t);
  }
  pull(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return a(), e = s.intounderlyingsource_pull(this.__wbg_ptr, _(t)), d(e);
  }
};
Symbol.dispose && (j.prototype[Symbol.dispose] = j.prototype.free);
var R = class i2 {
  static {
    __name(this, "i");
  }
  static __wrap(t) {
    let e = Object.create(i2.prototype);
    return e.__wbg_ptr = t, Object.defineProperty(e, "__wbg_inst", { value: f, writable: true }), X.register(e, { ptr: t, instance: f }, e), e;
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, X.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_minifyconfig_free(t, 0);
  }
  get css() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.__wbg_get_minifyconfig_css(this.__wbg_ptr), t !== 0;
  }
  get html() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.__wbg_get_minifyconfig_html(this.__wbg_ptr), t !== 0;
  }
  get js() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.__wbg_get_minifyconfig_js(this.__wbg_ptr), t !== 0;
  }
  set css(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_minifyconfig_css(this.__wbg_ptr, t);
  }
  set html(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_minifyconfig_html(this.__wbg_ptr, t);
  }
  set js(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_minifyconfig_js(this.__wbg_ptr, t);
  }
};
Symbol.dispose && (R.prototype[Symbol.dispose] = R.prototype.free);
var O = class {
  static {
    __name(this, "O");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, Y.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_pluginroomlog_free(t, 0);
  }
  alarm() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.pluginroomlog_alarm(this.__wbg_ptr), d(t);
  }
  fetch(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return a(), e = s.pluginroomlog_fetch(this.__wbg_ptr, _(t)), d(e);
  }
  constructor(t, e) {
    let n;
    return a(), n = s.pluginroomlog_new(_(t), _(e)), this.__wbg_ptr = n, Object.defineProperty(this, "__wbg_inst", { value: f, writable: true }), Y.register(this, { ptr: n, instance: f }, this), this;
  }
  webSocketClose(t, e, n, o) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let u = m(n, s.__wbindgen_export, s.__wbindgen_export2), g = h, l;
    return a(), l = s.pluginroomlog_webSocketClose(this.__wbg_ptr, _(t), e, u, g, o), d(l);
  }
  webSocketError(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return a(), n = s.pluginroomlog_webSocketError(this.__wbg_ptr, _(t), _(e)), d(n);
  }
  webSocketMessage(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return a(), n = s.pluginroomlog_webSocketMessage(this.__wbg_ptr, _(t), _(e)), d(n);
  }
};
Symbol.dispose && (O.prototype[Symbol.dispose] = O.prototype.free);
var P = class {
  static {
    __name(this, "P");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, yt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_r2range_free(t, 0);
  }
  get length() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
      let n = s.__wbindgen_add_to_stack_pointer(-16);
      a(), s.__wbg_get_r2range_length(n, this.__wbg_ptr);
      var t = b().getInt32(n + 0, true), e = b().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get offset() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
      let n = s.__wbindgen_add_to_stack_pointer(-16);
      a(), s.__wbg_get_r2range_offset(n, this.__wbg_ptr);
      var t = b().getInt32(n + 0, true), e = b().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get suffix() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
      let n = s.__wbindgen_add_to_stack_pointer(-16);
      a(), s.__wbg_get_r2range_suffix(n, this.__wbg_ptr);
      var t = b().getInt32(n + 0, true), e = b().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  set length(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_r2range_length(this.__wbg_ptr, !w(t), w(t) ? 0 : t);
  }
  set offset(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_r2range_offset(this.__wbg_ptr, !w(t), w(t) ? 0 : t);
  }
  set suffix(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    a(), s.__wbg_set_r2range_suffix(this.__wbg_ptr, !w(t), w(t) ? 0 : t);
  }
};
Symbol.dispose && (P.prototype[Symbol.dispose] = P.prototype.free);
var T = class {
  static {
    __name(this, "T");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, Z.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    a(), s.__wbg_userinbox_free(t, 0);
  }
  alarm() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return a(), t = s.userinbox_alarm(this.__wbg_ptr), d(t);
  }
  fetch(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return a(), e = s.userinbox_fetch(this.__wbg_ptr, _(t)), d(e);
  }
  constructor(t, e) {
    let n;
    return a(), n = s.userinbox_new(_(t), _(e)), this.__wbg_ptr = n, Object.defineProperty(this, "__wbg_inst", { value: f, writable: true }), Z.register(this, { ptr: n, instance: f }, this), this;
  }
  webSocketClose(t, e, n, o) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let u = m(n, s.__wbindgen_export, s.__wbindgen_export2), g = h, l;
    return a(), l = s.userinbox_webSocketClose(this.__wbg_ptr, _(t), e, u, g, o), d(l);
  }
  webSocketError(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return a(), n = s.userinbox_webSocketError(this.__wbg_ptr, _(t), _(e)), d(n);
  }
  webSocketMessage(t, e) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== f) throw new Error("Invalid stale object from previous Wasm instance");
    let n;
    return a(), n = s.userinbox_webSocketMessage(this.__wbg_ptr, _(t), _(e)), d(n);
  }
};
Symbol.dispose && (T.prototype[Symbol.dispose] = T.prototype.free);
function H() {
  f++, S = null, M = null, typeof numBytesDecoded < "u" && (numBytesDecoded = 0), typeof h < "u" && (h = 0), typeof x < "u" && (x = new Array(1024).fill(void 0), x = x.concat([void 0, null, true, false]), typeof E < "u" && (E = x.length)), ct = false, $ = new WebAssembly.Instance(et, st()), s = $.exports, s.__wbindgen_start();
}
__name(H, "H");
function nt() {
  let i3;
  return a(), i3 = s.__worker_init_state(), d(i3);
}
__name(nt, "nt");
function rt(i3, t, e) {
  let n;
  return a(), n = s.fetch(_(i3), _(t), _(e)), d(n);
}
__name(rt, "rt");
function _t() {
  a(), s.init();
}
__name(_t, "_t");
function ot(i3, t, e) {
  let n;
  return a(), n = s.scheduled(_(i3), _(t), _(e)), d(n);
}
__name(ot, "ot");
function it() {
  a(), s.start();
}
__name(it, "it");
function st() {
  return { __proto__: null, "./index_bg.js": { __proto__: null, __wbg_Error_bce6d499ff0a4aff: /* @__PURE__ */ __name(function(t, e) {
    let n = Error(p(t, e));
    return _(n);
  }, "__wbg_Error_bce6d499ff0a4aff"), __wbg_Number_b7972a139bfbfdf0: /* @__PURE__ */ __name(function(t) {
    return Number(r(t));
  }, "__wbg_Number_b7972a139bfbfdf0"), __wbg_String_8564e559799eccda: /* @__PURE__ */ __name(function(t, e) {
    let n = String(r(e)), o = m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
    b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
  }, "__wbg_String_8564e559799eccda"), __wbg___wbindgen_bigint_get_as_i64_410e28c7b761ad83: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e), o = typeof n == "bigint" ? n : void 0;
    b().setBigInt64(t + 8, w(o) ? BigInt(0) : o, true), b().setInt32(t + 0, !w(o), true);
  }, "__wbg___wbindgen_bigint_get_as_i64_410e28c7b761ad83"), __wbg___wbindgen_boolean_get_2304fb8c853028c8: /* @__PURE__ */ __name(function(t) {
    let e = r(t), n = typeof e == "boolean" ? e : void 0;
    return w(n) ? 16777215 : n ? 1 : 0;
  }, "__wbg___wbindgen_boolean_get_2304fb8c853028c8"), __wbg___wbindgen_debug_string_edece8177ad01481: /* @__PURE__ */ __name(function(t, e) {
    let n = N(r(e)), o = m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
    b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
  }, "__wbg___wbindgen_debug_string_edece8177ad01481"), __wbg___wbindgen_in_07056af4f902c445: /* @__PURE__ */ __name(function(t, e) {
    return r(t) in r(e);
  }, "__wbg___wbindgen_in_07056af4f902c445"), __wbg___wbindgen_is_bigint_aeae3893f30ed54e: /* @__PURE__ */ __name(function(t) {
    return typeof r(t) == "bigint";
  }, "__wbg___wbindgen_is_bigint_aeae3893f30ed54e"), __wbg___wbindgen_is_function_5cd60d5cf78b4eef: /* @__PURE__ */ __name(function(t) {
    return typeof r(t) == "function";
  }, "__wbg___wbindgen_is_function_5cd60d5cf78b4eef"), __wbg___wbindgen_is_null_2042690d351e14f0: /* @__PURE__ */ __name(function(t) {
    return r(t) === null;
  }, "__wbg___wbindgen_is_null_2042690d351e14f0"), __wbg___wbindgen_is_null_or_undefined_74c58242e8529df3: /* @__PURE__ */ __name(function(t) {
    return r(t) == null;
  }, "__wbg___wbindgen_is_null_or_undefined_74c58242e8529df3"), __wbg___wbindgen_is_object_b4593df85baada48: /* @__PURE__ */ __name(function(t) {
    let e = r(t);
    return typeof e == "object" && e !== null;
  }, "__wbg___wbindgen_is_object_b4593df85baada48"), __wbg___wbindgen_is_string_dde0fd9020db4434: /* @__PURE__ */ __name(function(t) {
    return typeof r(t) == "string";
  }, "__wbg___wbindgen_is_string_dde0fd9020db4434"), __wbg___wbindgen_is_undefined_35bb9f4c7fd651d5: /* @__PURE__ */ __name(function(t) {
    return r(t) === void 0;
  }, "__wbg___wbindgen_is_undefined_35bb9f4c7fd651d5"), __wbg___wbindgen_jsval_eq_c0ed08b3e0f393b9: /* @__PURE__ */ __name(function(t, e) {
    return r(t) === r(e);
  }, "__wbg___wbindgen_jsval_eq_c0ed08b3e0f393b9"), __wbg___wbindgen_jsval_loose_eq_0ad77b7717db155c: /* @__PURE__ */ __name(function(t, e) {
    return r(t) == r(e);
  }, "__wbg___wbindgen_jsval_loose_eq_0ad77b7717db155c"), __wbg___wbindgen_number_get_f73a1244370fcc2c: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e), o = typeof n == "number" ? n : void 0;
    b().setFloat64(t + 8, w(o) ? 0 : o, true), b().setInt32(t + 0, !w(o), true);
  }, "__wbg___wbindgen_number_get_f73a1244370fcc2c"), __wbg___wbindgen_string_get_d109740c0d18f4d7: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e), o = typeof n == "string" ? n : void 0;
    var u = w(o) ? 0 : m(o, s.__wbindgen_export, s.__wbindgen_export2), g = h;
    b().setInt32(t + 4, g, true), b().setInt32(t + 0, u, true);
  }, "__wbg___wbindgen_string_get_d109740c0d18f4d7"), __wbg___wbindgen_throw_9c31b086c2b26051: /* @__PURE__ */ __name(function(t, e) {
    throw new Error(p(t, e));
  }, "__wbg___wbindgen_throw_9c31b086c2b26051"), __wbg__wbg_cb_unref_3fa391f3fcdb55f8: /* @__PURE__ */ __name(function(t) {
    r(t)._wbg_cb_unref();
  }, "__wbg__wbg_cb_unref_3fa391f3fcdb55f8"), __wbg_acceptWebSocket_5d5a1f034c9bec0e: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).acceptWebSocket(r(e));
    }, arguments);
  }, "__wbg_acceptWebSocket_5d5a1f034c9bec0e"), __wbg_all_5a0f50ed86bbeec0: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).all();
      return _(e);
    }, arguments);
  }, "__wbg_all_5a0f50ed86bbeec0"), __wbg_append_263958599fd198c1: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o, u) {
      r(t).append(p(e, n), p(o, u));
    }, arguments);
  }, "__wbg_append_263958599fd198c1"), __wbg_arrayBuffer_eaaa68d56d86ba12: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).arrayBuffer();
      return _(e);
    }, arguments);
  }, "__wbg_arrayBuffer_eaaa68d56d86ba12"), __wbg_arrayBuffer_f2e138a689c7f4f9: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).arrayBuffer();
      return _(e);
    }, arguments);
  }, "__wbg_arrayBuffer_f2e138a689c7f4f9"), __wbg_batch_4025e434f794bf9f: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).batch(d(e));
      return _(n);
    }, arguments);
  }, "__wbg_batch_4025e434f794bf9f"), __wbg_bind_047aba25eb382b5a: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).bind(...d(e));
      return _(n);
    }, arguments);
  }, "__wbg_bind_047aba25eb382b5a"), __wbg_bodyUsed_3b89bb194fc66fd9: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      return r(t).bodyUsed;
    }, arguments);
  }, "__wbg_bodyUsed_3b89bb194fc66fd9"), __wbg_body_0f1e9e98336ac0fa: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).body;
      return _(e);
    }, arguments);
  }, "__wbg_body_0f1e9e98336ac0fa"), __wbg_body_acbb5ec9cd18657f: /* @__PURE__ */ __name(function(t) {
    let e = r(t).body;
    return w(e) ? 0 : _(e);
  }, "__wbg_body_acbb5ec9cd18657f"), __wbg_buffer_8d6798e32d1afd34: /* @__PURE__ */ __name(function(t) {
    let e = r(t).buffer;
    return _(e);
  }, "__wbg_buffer_8d6798e32d1afd34"), __wbg_byobRequest_9d8c3b7b2f692560: /* @__PURE__ */ __name(function(t) {
    let e = r(t).byobRequest;
    return w(e) ? 0 : _(e);
  }, "__wbg_byobRequest_9d8c3b7b2f692560"), __wbg_byteLength_c0cecdd68fab1693: /* @__PURE__ */ __name(function(t) {
    return r(t).byteLength;
  }, "__wbg_byteLength_c0cecdd68fab1693"), __wbg_byteOffset_3791b0030cc3b490: /* @__PURE__ */ __name(function(t) {
    return r(t).byteOffset;
  }, "__wbg_byteOffset_3791b0030cc3b490"), __wbg_cacheControl_1ee7dc2a98b997c8: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).cacheControl;
      var o = w(n) ? 0 : m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_cacheControl_1ee7dc2a98b997c8"), __wbg_cacheExpiry_5c16c9ad058c420c: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).cacheExpiry;
      return w(e) ? 0 : _(e);
    }, arguments);
  }, "__wbg_cacheExpiry_5c16c9ad058c420c"), __wbg_call_084ee3e860ee9f92: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o, u) {
      let g = r(t).call(r(e), r(n), r(o), r(u));
      return _(g);
    }, arguments);
  }, "__wbg_call_084ee3e860ee9f92"), __wbg_call_13665d9f14390edc: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).call(r(e));
      return _(n);
    }, arguments);
  }, "__wbg_call_13665d9f14390edc"), __wbg_call_dfde26266607c996: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = r(t).call(r(e), r(n));
      return _(o);
    }, arguments);
  }, "__wbg_call_dfde26266607c996"), __wbg_call_faa0a261f288f846: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o) {
      let u = r(t).call(r(e), r(n), r(o));
      return _(u);
    }, arguments);
  }, "__wbg_call_faa0a261f288f846"), __wbg_cancel_bee68d5707c614fb: /* @__PURE__ */ __name(function(t) {
    let e = r(t).cancel();
    return _(e);
  }, "__wbg_cancel_bee68d5707c614fb"), __wbg_catch_ec5061a695c26496: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t).catch(r(e));
    return _(n);
  }, "__wbg_catch_ec5061a695c26496"), __wbg_cause_af1d0ccfb7354a29: /* @__PURE__ */ __name(function(t) {
    let e = r(t).cause;
    return _(e);
  }, "__wbg_cause_af1d0ccfb7354a29"), __wbg_cf_19e06ec190adc114: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).cf;
      return w(e) ? 0 : _(e);
    }, arguments);
  }, "__wbg_cf_19e06ec190adc114"), __wbg_cf_99dfada43d8986a1: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).cf;
      return w(e) ? 0 : _(e);
    }, arguments);
  }, "__wbg_cf_99dfada43d8986a1"), __wbg_clearTimeout_b339cb81aa470a3e: /* @__PURE__ */ __name(function(t, e) {
    r(t).clearTimeout(e);
  }, "__wbg_clearTimeout_b339cb81aa470a3e"), __wbg_close_53179a3d37ed525d: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      r(t).close();
    }, arguments);
  }, "__wbg_close_53179a3d37ed525d"), __wbg_close_807d553ef8405788: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      r(t).close();
    }, arguments);
  }, "__wbg_close_807d553ef8405788"), __wbg_close_e1f28ed6c57d2b8b: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o) {
      r(t).close(e, p(n, o));
    }, arguments);
  }, "__wbg_close_e1f28ed6c57d2b8b"), __wbg_constructor_9a9e391694baf7d0: /* @__PURE__ */ __name(function(t) {
    let e = r(t).constructor;
    return _(e);
  }, "__wbg_constructor_9a9e391694baf7d0"), __wbg_contentDisposition_56c2b44ee6f8c4e1: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).contentDisposition;
      var o = w(n) ? 0 : m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_contentDisposition_56c2b44ee6f8c4e1"), __wbg_contentEncoding_7b34d517d294b522: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).contentEncoding;
      var o = w(n) ? 0 : m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_contentEncoding_7b34d517d294b522"), __wbg_contentLanguage_e6d5ea9f6a28704f: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).contentLanguage;
      var o = w(n) ? 0 : m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_contentLanguage_e6d5ea9f6a28704f"), __wbg_contentType_83a3313979fe118b: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).contentType;
      var o = w(n) ? 0 : m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_contentType_83a3313979fe118b"), __wbg_cron_4572e7e7bfe66d10: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).cron, o = m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_cron_4572e7e7bfe66d10"), __wbg_crypto_38df2bab126b63dc: /* @__PURE__ */ __name(function(t) {
    let e = r(t).crypto;
    return _(e);
  }, "__wbg_crypto_38df2bab126b63dc"), __wbg_cursor_5deab7cbb94d5bde: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).cursor;
      var o = w(n) ? 0 : m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_cursor_5deab7cbb94d5bde"), __wbg_deleteAlarm_e9c658c448af8592: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).deleteAlarm(d(e));
      return _(n);
    }, arguments);
  }, "__wbg_deleteAlarm_e9c658c448af8592"), __wbg_deleteAll_21b4ef924e1c4786: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).deleteAll();
      return _(e);
    }, arguments);
  }, "__wbg_deleteAll_21b4ef924e1c4786"), __wbg_delete_1fd09b78af14ab2b: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o, u;
      try {
        o = e, u = n;
        let g = r(t).delete(p(e, n));
        return _(g);
      } finally {
        a(), s.__wbindgen_export4(o, u, 1);
      }
    }, arguments);
  }, "__wbg_delete_1fd09b78af14ab2b"), __wbg_deserializeAttachment_81c08b1889078159: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).deserializeAttachment();
      return _(e);
    }, arguments);
  }, "__wbg_deserializeAttachment_81c08b1889078159"), __wbg_done_54b8da57023b7ed2: /* @__PURE__ */ __name(function(t) {
    return r(t).done;
  }, "__wbg_done_54b8da57023b7ed2"), __wbg_enqueue_c3ce0a986a355a8c: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).enqueue(r(e));
    }, arguments);
  }, "__wbg_enqueue_c3ce0a986a355a8c"), __wbg_entries_564a7e8b1e54ede5: /* @__PURE__ */ __name(function(t) {
    let e = Object.entries(r(t));
    return _(e);
  }, "__wbg_entries_564a7e8b1e54ede5"), __wbg_entries_8c373da97ea5ada5: /* @__PURE__ */ __name(function(t) {
    let e = r(t).entries();
    return _(e);
  }, "__wbg_entries_8c373da97ea5ada5"), __wbg_error_19d45ba06d627441: /* @__PURE__ */ __name(function(t, e) {
    console.error(r(t), r(e));
  }, "__wbg_error_19d45ba06d627441"), __wbg_error_a6fa202b58aa1cd3: /* @__PURE__ */ __name(function(t, e) {
    let n, o;
    try {
      n = t, o = e, console.error(p(t, e));
    } finally {
      a(), s.__wbindgen_export4(n, o, 1);
    }
  }, "__wbg_error_a6fa202b58aa1cd3"), __wbg_error_f085d7e62279b703: /* @__PURE__ */ __name(function(t) {
    console.error(r(t));
  }, "__wbg_error_f085d7e62279b703"), __wbg_exec_48dc3872d716d628: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o) {
      let u = r(t).exec(p(e, n), ...d(o));
      return _(u);
    }, arguments);
  }, "__wbg_exec_48dc3872d716d628"), __wbg_fetch_16af90a35a519bfa: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).fetch(r(e));
      return _(n);
    }, arguments);
  }, "__wbg_fetch_16af90a35a519bfa"), __wbg_fetch_42a2f5dff6268926: /* @__PURE__ */ __name(function(t, e, n, o) {
    let u = r(t).fetch(p(e, n), r(o));
    return _(u);
  }, "__wbg_fetch_42a2f5dff6268926"), __wbg_fetch_7bedf02f4d284391: /* @__PURE__ */ __name(function(t, e, n) {
    let o = r(t).fetch(r(e), r(n));
    return _(o);
  }, "__wbg_fetch_7bedf02f4d284391"), __wbg_first_97b69bd0708feb7b: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = r(t).first(e === 0 ? void 0 : p(e, n));
      return _(o);
    }, arguments);
  }, "__wbg_first_97b69bd0708feb7b"), __wbg_getAlarm_b19e32e9d30b9fc0: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).getAlarm(d(e));
      return _(n);
    }, arguments);
  }, "__wbg_getAlarm_b19e32e9d30b9fc0"), __wbg_getRandomValues_76dfc69825c9c552: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      globalThis.crypto.getRandomValues(F(t, e));
    }, arguments);
  }, "__wbg_getRandomValues_76dfc69825c9c552"), __wbg_getRandomValues_c44a50d8cfdaebeb: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).getRandomValues(r(e));
    }, arguments);
  }, "__wbg_getRandomValues_c44a50d8cfdaebeb"), __wbg_getRandomValues_ef12552bf5acd2fe: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      globalThis.crypto.getRandomValues(F(t, e));
    }, arguments);
  }, "__wbg_getRandomValues_ef12552bf5acd2fe"), __wbg_getReader_9facd4f899beac89: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).getReader();
      return _(e);
    }, arguments);
  }, "__wbg_getReader_9facd4f899beac89"), __wbg_getTime_09f1dd40a44edb30: /* @__PURE__ */ __name(function(t) {
    return r(t).getTime();
  }, "__wbg_getTime_09f1dd40a44edb30"), __wbg_getWebSockets_374c518f5a97d39c: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).getWebSockets(), o = V(n, s.__wbindgen_export), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_getWebSockets_374c518f5a97d39c"), __wbg_get_0b3f3bb74d16b7ad: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o) {
      let u = r(e).get(p(n, o));
      var g = w(u) ? 0 : m(u, s.__wbindgen_export, s.__wbindgen_export2), l = h;
      b().setInt32(t + 4, l, true), b().setInt32(t + 0, g, true);
    }, arguments);
  }, "__wbg_get_0b3f3bb74d16b7ad"), __wbg_get_2b049bb39a3f3ed5: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = r(t).get(p(e, n));
      return _(o);
    }, arguments);
  }, "__wbg_get_2b049bb39a3f3ed5"), __wbg_get_3e9a707ab7d352eb: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = Reflect.get(r(t), r(e));
      return _(n);
    }, arguments);
  }, "__wbg_get_3e9a707ab7d352eb"), __wbg_get_8e466294dfec2263: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o) {
      let u, g;
      try {
        u = e, g = n;
        let l = r(t).get(p(e, n), d(o));
        return _(l);
      } finally {
        a(), s.__wbindgen_export4(u, g, 1);
      }
    }, arguments);
  }, "__wbg_get_8e466294dfec2263"), __wbg_get_98fdf51d029a75eb: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t)[e >>> 0];
    return _(n);
  }, "__wbg_get_98fdf51d029a75eb"), __wbg_get_aa415c1943040683: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = Reflect.get(r(t), e >>> 0);
      return _(n);
    }, arguments);
  }, "__wbg_get_aa415c1943040683"), __wbg_get_dcf82ab8aad1a593: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = Reflect.get(r(t), r(e));
      return _(n);
    }, arguments);
  }, "__wbg_get_dcf82ab8aad1a593"), __wbg_get_done_06210bfbda89c407: /* @__PURE__ */ __name(function(t) {
    let e = r(t).done;
    return w(e) ? 16777215 : e ? 1 : 0;
  }, "__wbg_get_done_06210bfbda89c407"), __wbg_get_ed0bf36cb3b866e4: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).get(r(e));
      return _(n);
    }, arguments);
  }, "__wbg_get_ed0bf36cb3b866e4"), __wbg_get_f591d97c88ae94ef: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = Reflect.get(r(t), r(e));
      return w(n) ? 0 : _(n);
    }, arguments);
  }, "__wbg_get_f591d97c88ae94ef"), __wbg_get_unchecked_1dfe6d05ad91d9b7: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t)[e >>> 0];
    return _(n);
  }, "__wbg_get_unchecked_1dfe6d05ad91d9b7"), __wbg_get_value_31eb9abef97d98cb: /* @__PURE__ */ __name(function(t) {
    let e = r(t).value;
    return _(e);
  }, "__wbg_get_value_31eb9abef97d98cb"), __wbg_get_with_ref_key_6412cf3094599694: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t)[r(e)];
    return _(n);
  }, "__wbg_get_with_ref_key_6412cf3094599694"), __wbg_headers_18f39f24d3837dc1: /* @__PURE__ */ __name(function(t) {
    let e = r(t).headers;
    return _(e);
  }, "__wbg_headers_18f39f24d3837dc1"), __wbg_headers_4cfb0c75793d7a8d: /* @__PURE__ */ __name(function(t) {
    let e = r(t).headers;
    return _(e);
  }, "__wbg_headers_4cfb0c75793d7a8d"), __wbg_httpMetadata_62cc888a6ffd5991: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).httpMetadata;
      return _(e);
    }, arguments);
  }, "__wbg_httpMetadata_62cc888a6ffd5991"), __wbg_idFromName_834be31641b23754: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = r(t).idFromName(p(e, n));
      return _(o);
    }, arguments);
  }, "__wbg_idFromName_834be31641b23754"), __wbg_instanceId_d6c260a59e274d0b: /* @__PURE__ */ __name(function(t) {
    return r(t).instanceId;
  }, "__wbg_instanceId_d6c260a59e274d0b"), __wbg_instanceof_ArrayBuffer_53db37b06f6b9afe: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof ArrayBuffer;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_ArrayBuffer_53db37b06f6b9afe"), __wbg_instanceof_Error_b3f7e146d654031a: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Error;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Error_b3f7e146d654031a"), __wbg_instanceof_Map_16f217b9a2a08d8c: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Map;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Map_16f217b9a2a08d8c"), __wbg_instanceof_ReadableStream_9a3d74fc91aa9c55: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof ReadableStream;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_ReadableStream_9a3d74fc91aa9c55"), __wbg_instanceof_Response_ecfc823e8fb354e2: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Response;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Response_ecfc823e8fb354e2"), __wbg_instanceof_Uint8Array_abd07d4bd221d50b: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Uint8Array;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Uint8Array_abd07d4bd221d50b"), __wbg_isArray_94898ed3aad6947b: /* @__PURE__ */ __name(function(t) {
    return Array.isArray(r(t));
  }, "__wbg_isArray_94898ed3aad6947b"), __wbg_isSafeInteger_01e964d144ad3a55: /* @__PURE__ */ __name(function(t) {
    return Number.isSafeInteger(r(t));
  }, "__wbg_isSafeInteger_01e964d144ad3a55"), __wbg_iterator_1441b47f341dc34f: /* @__PURE__ */ __name(function() {
    return _(Symbol.iterator);
  }, "__wbg_iterator_1441b47f341dc34f"), __wbg_json_4eede11b9930d02e: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).json();
      return _(e);
    }, arguments);
  }, "__wbg_json_4eede11b9930d02e"), __wbg_key_d255db9220438ac6: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).key, o = m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_key_d255db9220438ac6"), __wbg_keys_610666c87d9e3542: /* @__PURE__ */ __name(function(t) {
    let e = r(t).keys();
    return _(e);
  }, "__wbg_keys_610666c87d9e3542"), __wbg_length_2591a0f4f659a55c: /* @__PURE__ */ __name(function(t) {
    return r(t).length;
  }, "__wbg_length_2591a0f4f659a55c"), __wbg_length_56fcd3e2b7e0299d: /* @__PURE__ */ __name(function(t) {
    return r(t).length;
  }, "__wbg_length_56fcd3e2b7e0299d"), __wbg_list_2faa472830df8101: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(t).list(d(e));
      return _(n);
    }, arguments);
  }, "__wbg_list_2faa472830df8101"), __wbg_log_eb752234eec406d1: /* @__PURE__ */ __name(function(t) {
    console.log(r(t));
  }, "__wbg_log_eb752234eec406d1"), __wbg_message_324ac511aeaf710e: /* @__PURE__ */ __name(function(t) {
    let e = r(t).message;
    return _(e);
  }, "__wbg_message_324ac511aeaf710e"), __wbg_meta_d944de36cf589873: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).meta;
      return _(e);
    }, arguments);
  }, "__wbg_meta_d944de36cf589873"), __wbg_method_eadeb6c481ed3b2d: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e).method, o = m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
    b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
  }, "__wbg_method_eadeb6c481ed3b2d"), __wbg_minifyconfig_new: /* @__PURE__ */ __name(function(t) {
    let e = R.__wrap(t);
    return _(e);
  }, "__wbg_minifyconfig_new"), __wbg_msCrypto_bd5a034af96bcba6: /* @__PURE__ */ __name(function(t) {
    let e = r(t).msCrypto;
    return _(e);
  }, "__wbg_msCrypto_bd5a034af96bcba6"), __wbg_name_7eee4ed497d7c416: /* @__PURE__ */ __name(function(t) {
    let e = r(t).name;
    return _(e);
  }, "__wbg_name_7eee4ed497d7c416"), __wbg_name_d09e9b472d8320d3: /* @__PURE__ */ __name(function(t) {
    let e = r(t).name;
    return _(e);
  }, "__wbg_name_d09e9b472d8320d3"), __wbg_new_02d162bc6cf02f60: /* @__PURE__ */ __name(function() {
    let t = new Object();
    return _(t);
  }, "__wbg_new_02d162bc6cf02f60"), __wbg_new_070df68d66325372: /* @__PURE__ */ __name(function() {
    return _(/* @__PURE__ */ new Map());
  }, "__wbg_new_070df68d66325372"), __wbg_new_0_2722fcdb71a888a6: /* @__PURE__ */ __name(function() {
    return _(/* @__PURE__ */ new Date());
  }, "__wbg_new_0_2722fcdb71a888a6"), __wbg_new_0c6c5a5d2c78558a: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = new FixedLengthStream(t >>> 0);
      return _(e);
    }, arguments);
  }, "__wbg_new_0c6c5a5d2c78558a"), __wbg_new_1f236d63ba0c4784: /* @__PURE__ */ __name(function(t, e) {
    let n = new Error(p(t, e));
    return _(n);
  }, "__wbg_new_1f236d63ba0c4784"), __wbg_new_227d7c05414eb861: /* @__PURE__ */ __name(function() {
    let t = new Error();
    return _(t);
  }, "__wbg_new_227d7c05414eb861"), __wbg_new_310879b66b6e95e1: /* @__PURE__ */ __name(function() {
    let t = new Array();
    return _(t);
  }, "__wbg_new_310879b66b6e95e1"), __wbg_new_7ddec6de44ff8f5d: /* @__PURE__ */ __name(function(t) {
    let e = new Uint8Array(r(t));
    return _(e);
  }, "__wbg_new_7ddec6de44ff8f5d"), __wbg_new_7ea411c80558cceb: /* @__PURE__ */ __name(function() {
    return c(function() {
      let t = new WebSocketPair();
      return _(t);
    }, arguments);
  }, "__wbg_new_7ea411c80558cceb"), __wbg_new_859b9002e2668e82: /* @__PURE__ */ __name(function(t) {
    let e = new Date(r(t));
    return _(e);
  }, "__wbg_new_859b9002e2668e82"), __wbg_new_big_int_8296d353ab964b93: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = new FixedLengthStream(d(t));
      return _(e);
    }, arguments);
  }, "__wbg_new_big_int_8296d353ab964b93"), __wbg_new_ee0be486d8f01282: /* @__PURE__ */ __name(function() {
    return c(function() {
      let t = new Headers();
      return _(t);
    }, arguments);
  }, "__wbg_new_ee0be486d8f01282"), __wbg_new_from_slice_269e35316ed2d061: /* @__PURE__ */ __name(function(t, e) {
    let n = new Uint8Array(F(t, e));
    return _(n);
  }, "__wbg_new_from_slice_269e35316ed2d061"), __wbg_new_typed_c072c4ce9a2a0cdf: /* @__PURE__ */ __name(function(t, e) {
    try {
      var n = { a: t, b: e }, o = /* @__PURE__ */ __name((g, l) => {
        let y = n.a;
        n.a = 0;
        try {
          return gt(y, n.b, g, l);
        } finally {
          n.a = y;
        }
      }, "o");
      let u = new Promise(o);
      return _(u);
    } finally {
      n.a = 0;
    }
  }, "__wbg_new_typed_c072c4ce9a2a0cdf"), __wbg_new_with_byte_offset_and_length_a87e79143162d67f: /* @__PURE__ */ __name(function(t, e, n) {
    let o = new Uint8Array(r(t), e >>> 0, n >>> 0);
    return _(o);
  }, "__wbg_new_with_byte_offset_and_length_a87e79143162d67f"), __wbg_new_with_headers_444c1c017700c78e: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = new Headers(r(t));
      return _(e);
    }, arguments);
  }, "__wbg_new_with_headers_444c1c017700c78e"), __wbg_new_with_into_underlying_source_fd904252f385f59c: /* @__PURE__ */ __name(function(t, e) {
    let n = new ReadableStream(j.__wrap(t), d(e));
    return _(n);
  }, "__wbg_new_with_into_underlying_source_fd904252f385f59c"), __wbg_new_with_length_99887c91eae4abab: /* @__PURE__ */ __name(function(t) {
    let e = new Uint8Array(t >>> 0);
    return _(e);
  }, "__wbg_new_with_length_99887c91eae4abab"), __wbg_new_with_opt_buffer_source_and_init_b007ac889af621a0: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = new Response(r(t), r(e));
      return _(n);
    }, arguments);
  }, "__wbg_new_with_opt_buffer_source_and_init_b007ac889af621a0"), __wbg_new_with_opt_readable_stream_and_init_802af9500a04b75d: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = new Response(r(t), r(e));
      return _(n);
    }, arguments);
  }, "__wbg_new_with_opt_readable_stream_and_init_802af9500a04b75d"), __wbg_new_with_opt_str_and_init_1dd0a9ed589dcc68: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = new Response(t === 0 ? void 0 : p(t, e), r(n));
      return _(o);
    }, arguments);
  }, "__wbg_new_with_opt_str_and_init_1dd0a9ed589dcc68"), __wbg_new_with_str_and_init_ffe9977c986ea039: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = new Request(p(t, e), r(n));
      return _(o);
    }, arguments);
  }, "__wbg_new_with_str_and_init_ffe9977c986ea039"), __wbg_next_2a4e19f4f5083b0f: /* @__PURE__ */ __name(function(t) {
    let e = r(t).next;
    return _(e);
  }, "__wbg_next_2a4e19f4f5083b0f"), __wbg_next_6429a146bf756f93: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).next();
      return _(e);
    }, arguments);
  }, "__wbg_next_6429a146bf756f93"), __wbg_node_84ea875411254db1: /* @__PURE__ */ __name(function(t) {
    let e = r(t).node;
    return _(e);
  }, "__wbg_node_84ea875411254db1"), __wbg_objects_b89d04dd29c5a815: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      let n = r(e).objects, o = V(n, s.__wbindgen_export), u = h;
      b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
    }, arguments);
  }, "__wbg_objects_b89d04dd29c5a815"), __wbg_pipeTo_1f92d4713b959234: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t).pipeTo(r(e));
    return _(n);
  }, "__wbg_pipeTo_1f92d4713b959234"), __wbg_prepare_faefb39d63d9c2f1: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = r(t).prepare(p(e, n));
      return _(o);
    }, arguments);
  }, "__wbg_prepare_faefb39d63d9c2f1"), __wbg_process_44c7a14e11e9f69e: /* @__PURE__ */ __name(function(t) {
    let e = r(t).process;
    return _(e);
  }, "__wbg_process_44c7a14e11e9f69e"), __wbg_prototypesetcall_5f9bdc8d75e07276: /* @__PURE__ */ __name(function(t, e, n) {
    Uint8Array.prototype.set.call(F(t, e), r(n));
  }, "__wbg_prototypesetcall_5f9bdc8d75e07276"), __wbg_push_b77c476b01548d0a: /* @__PURE__ */ __name(function(t, e) {
    return r(t).push(r(e));
  }, "__wbg_push_b77c476b01548d0a"), __wbg_put_9e529cec370ec674: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o, u) {
      let g, l;
      try {
        g = e, l = n;
        let y = r(t).put(p(e, n), d(o), d(u));
        return _(y);
      } finally {
        a(), s.__wbindgen_export4(g, l, 1);
      }
    }, arguments);
  }, "__wbg_put_9e529cec370ec674"), __wbg_put_ad54870ee3f82bce: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o) {
      let u = r(t).put(p(e, n), d(o));
      return _(u);
    }, arguments);
  }, "__wbg_put_ad54870ee3f82bce"), __wbg_queueMicrotask_78d584b53af520f5: /* @__PURE__ */ __name(function(t) {
    let e = r(t).queueMicrotask;
    return _(e);
  }, "__wbg_queueMicrotask_78d584b53af520f5"), __wbg_queueMicrotask_b39ea83c7f01971a: /* @__PURE__ */ __name(function(t) {
    queueMicrotask(r(t));
  }, "__wbg_queueMicrotask_b39ea83c7f01971a"), __wbg_randomFillSync_6c25eac9869eb53c: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).randomFillSync(d(e));
    }, arguments);
  }, "__wbg_randomFillSync_6c25eac9869eb53c"), __wbg_read_254bf22401498310: /* @__PURE__ */ __name(function(t) {
    let e = r(t).read();
    return _(e);
  }, "__wbg_read_254bf22401498310"), __wbg_readable_dd905e4142e3f69e: /* @__PURE__ */ __name(function(t) {
    let e = r(t).readable;
    return _(e);
  }, "__wbg_readable_dd905e4142e3f69e"), __wbg_releaseLock_65f356509fef84ac: /* @__PURE__ */ __name(function(t) {
    r(t).releaseLock();
  }, "__wbg_releaseLock_65f356509fef84ac"), __wbg_require_b4edbdcf3e2a1ef0: /* @__PURE__ */ __name(function() {
    return c(function() {
      let t = module.require;
      return _(t);
    }, arguments);
  }, "__wbg_require_b4edbdcf3e2a1ef0"), __wbg_resolve_d17db9352f5a220e: /* @__PURE__ */ __name(function(t) {
    let e = Promise.resolve(r(t));
    return _(e);
  }, "__wbg_resolve_d17db9352f5a220e"), __wbg_respond_0196e052b003e1db: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).respond(e >>> 0);
    }, arguments);
  }, "__wbg_respond_0196e052b003e1db"), __wbg_results_c65f55871a9fa6ec: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).results;
      return w(e) ? 0 : _(e);
    }, arguments);
  }, "__wbg_results_c65f55871a9fa6ec"), __wbg_run_052846663739b2b2: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).run();
      return _(e);
    }, arguments);
  }, "__wbg_run_052846663739b2b2"), __wbg_scheduledTime_8b1bfbedf2b74149: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      return r(t).scheduledTime;
    }, arguments);
  }, "__wbg_scheduledTime_8b1bfbedf2b74149"), __wbg_send_e1d2f71ce4473d1e: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      r(t).send(p(e, n));
    }, arguments);
  }, "__wbg_send_e1d2f71ce4473d1e"), __wbg_serializeAttachment_c4d74f8f5a845538: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).serializeAttachment(d(e));
    }, arguments);
  }, "__wbg_serializeAttachment_c4d74f8f5a845538"), __wbg_setAlarm_e02c0b57ae877305: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      let o = r(t).setAlarm(d(e), d(n));
      return _(o);
    }, arguments);
  }, "__wbg_setAlarm_e02c0b57ae877305"), __wbg_setTimeout_a2b48e67340623fd: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      return r(t).setTimeout(r(e), n);
    }, arguments);
  }, "__wbg_setTimeout_a2b48e67340623fd"), __wbg_set_24d0fa9e104112f9: /* @__PURE__ */ __name(function(t, e, n) {
    r(t).set(F(e, n));
  }, "__wbg_set_24d0fa9e104112f9"), __wbg_set_6be42768c690e380: /* @__PURE__ */ __name(function(t, e, n) {
    r(t)[d(e)] = d(n);
  }, "__wbg_set_6be42768c690e380"), __wbg_set_78ea6a19f4818587: /* @__PURE__ */ __name(function(t, e, n) {
    r(t)[e >>> 0] = d(n);
  }, "__wbg_set_78ea6a19f4818587"), __wbg_set_a0e911be3da02782: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n) {
      return Reflect.set(r(t), r(e), r(n));
    }, arguments);
  }, "__wbg_set_a0e911be3da02782"), __wbg_set_body_7f56457720e81672: /* @__PURE__ */ __name(function(t, e) {
    r(t).body = r(e);
  }, "__wbg_set_body_7f56457720e81672"), __wbg_set_cache_9ed01a3813d96de2: /* @__PURE__ */ __name(function(t, e) {
    r(t).cache = wt[e];
  }, "__wbg_set_cache_9ed01a3813d96de2"), __wbg_set_criticalError_d8a6b9f28ecd40df: /* @__PURE__ */ __name(function(t, e) {
    r(t).criticalError = e !== 0;
  }, "__wbg_set_criticalError_d8a6b9f28ecd40df"), __wbg_set_d57e5106f0271787: /* @__PURE__ */ __name(function() {
    return c(function(t, e, n, o, u) {
      r(t).set(p(e, n), p(o, u));
    }, arguments);
  }, "__wbg_set_d57e5106f0271787"), __wbg_set_facb7a5914e0fa39: /* @__PURE__ */ __name(function(t, e, n) {
    let o = r(t).set(r(e), r(n));
    return _(o);
  }, "__wbg_set_facb7a5914e0fa39"), __wbg_set_headers_179cf42797c4a305: /* @__PURE__ */ __name(function(t, e) {
    r(t).headers = r(e);
  }, "__wbg_set_headers_179cf42797c4a305"), __wbg_set_headers_97ed66619adb1e3e: /* @__PURE__ */ __name(function(t, e) {
    r(t).headers = r(e);
  }, "__wbg_set_headers_97ed66619adb1e3e"), __wbg_set_high_water_mark_6b567b5c596d9cc7: /* @__PURE__ */ __name(function(t, e) {
    r(t).highWaterMark = e;
  }, "__wbg_set_high_water_mark_6b567b5c596d9cc7"), __wbg_set_instanceId_84eed47796a1e874: /* @__PURE__ */ __name(function(t, e) {
    r(t).instanceId = e >>> 0;
  }, "__wbg_set_instanceId_84eed47796a1e874"), __wbg_set_method_4d69a1a7e34c0aca: /* @__PURE__ */ __name(function(t, e, n) {
    r(t).method = p(e, n);
  }, "__wbg_set_method_4d69a1a7e34c0aca"), __wbg_set_redirect_1c5253448ef852a8: /* @__PURE__ */ __name(function(t, e) {
    r(t).redirect = lt[e];
  }, "__wbg_set_redirect_1c5253448ef852a8"), __wbg_set_signal_2a5bd3615938edbc: /* @__PURE__ */ __name(function(t, e) {
    r(t).signal = r(e);
  }, "__wbg_set_signal_2a5bd3615938edbc"), __wbg_set_status_0ec29746ab53cab4: /* @__PURE__ */ __name(function(t, e) {
    r(t).status = e;
  }, "__wbg_set_status_0ec29746ab53cab4"), __wbg_size_63d2eeda5b4c5f35: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      return r(t).size;
    }, arguments);
  }, "__wbg_size_63d2eeda5b4c5f35"), __wbg_sql_93ebabfd320db007: /* @__PURE__ */ __name(function(t) {
    let e = r(t).sql;
    return _(e);
  }, "__wbg_sql_93ebabfd320db007"), __wbg_stack_3b0d974bbf31e44f: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e).stack, o = m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
    b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
  }, "__wbg_stack_3b0d974bbf31e44f"), __wbg_static_accessor_GLOBAL_THIS_02344c9b09eb08a9: /* @__PURE__ */ __name(function() {
    let t = typeof globalThis > "u" ? null : globalThis;
    return w(t) ? 0 : _(t);
  }, "__wbg_static_accessor_GLOBAL_THIS_02344c9b09eb08a9"), __wbg_static_accessor_GLOBAL_ac6d4ac874d5cd54: /* @__PURE__ */ __name(function() {
    let t = typeof global > "u" ? null : global;
    return w(t) ? 0 : _(t);
  }, "__wbg_static_accessor_GLOBAL_ac6d4ac874d5cd54"), __wbg_static_accessor_INIT_STATE_7aac697f52d7cd44: /* @__PURE__ */ __name(function() {
    return _(K);
  }, "__wbg_static_accessor_INIT_STATE_7aac697f52d7cd44"), __wbg_static_accessor_SELF_9b2406c23aeb2023: /* @__PURE__ */ __name(function() {
    let t = typeof self > "u" ? null : self;
    return w(t) ? 0 : _(t);
  }, "__wbg_static_accessor_SELF_9b2406c23aeb2023"), __wbg_static_accessor_WINDOW_b34d2126934e16ba: /* @__PURE__ */ __name(function() {
    let t = typeof window > "u" ? null : window;
    return w(t) ? 0 : _(t);
  }, "__wbg_static_accessor_WINDOW_b34d2126934e16ba"), __wbg_status_0853c9f5752c7ee2: /* @__PURE__ */ __name(function(t) {
    return r(t).status;
  }, "__wbg_status_0853c9f5752c7ee2"), __wbg_storage_2b553d342ee7a56e: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).storage;
      return _(e);
    }, arguments);
  }, "__wbg_storage_2b553d342ee7a56e"), __wbg_stringify_ef0c105b1ccc3849: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = JSON.stringify(r(t));
      return _(e);
    }, arguments);
  }, "__wbg_stringify_ef0c105b1ccc3849"), __wbg_subarray_7c6a0da8f3b4a1ba: /* @__PURE__ */ __name(function(t, e, n) {
    let o = r(t).subarray(e >>> 0, n >>> 0);
    return _(o);
  }, "__wbg_subarray_7c6a0da8f3b4a1ba"), __wbg_text_c4b3ac0bd8b9d0dd: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).text();
      return _(e);
    }, arguments);
  }, "__wbg_text_c4b3ac0bd8b9d0dd"), __wbg_then_837494e384b37459: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t).then(r(e));
    return _(n);
  }, "__wbg_then_837494e384b37459"), __wbg_then_bd927500e8905df2: /* @__PURE__ */ __name(function(t, e, n) {
    let o = r(t).then(r(e), r(n));
    return _(o);
  }, "__wbg_then_bd927500e8905df2"), __wbg_toArray_78807f10e025fbf1: /* @__PURE__ */ __name(function(t) {
    let e = r(t).toArray();
    return _(e);
  }, "__wbg_toArray_78807f10e025fbf1"), __wbg_toISOString_40e9e6e11e3480c5: /* @__PURE__ */ __name(function(t) {
    let e = r(t).toISOString();
    return _(e);
  }, "__wbg_toISOString_40e9e6e11e3480c5"), __wbg_truncated_2d6a13c9f6ac04fe: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      return r(t).truncated;
    }, arguments);
  }, "__wbg_truncated_2d6a13c9f6ac04fe"), __wbg_url_f1cddff1f5b9519a: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e).url, o = m(n, s.__wbindgen_export, s.__wbindgen_export2), u = h;
    b().setInt32(t + 4, u, true), b().setInt32(t + 0, o, true);
  }, "__wbg_url_f1cddff1f5b9519a"), __wbg_value_9cc0518af87a489c: /* @__PURE__ */ __name(function(t) {
    let e = r(t).value;
    return _(e);
  }, "__wbg_value_9cc0518af87a489c"), __wbg_versions_276b2795b1c6a219: /* @__PURE__ */ __name(function(t) {
    let e = r(t).versions;
    return _(e);
  }, "__wbg_versions_276b2795b1c6a219"), __wbg_view_1b637c097280508c: /* @__PURE__ */ __name(function(t) {
    let e = r(t).view;
    return w(e) ? 0 : _(e);
  }, "__wbg_view_1b637c097280508c"), __wbg_waitUntil_7da7840bb5af4807: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).waitUntil(r(e));
    }, arguments);
  }, "__wbg_waitUntil_7da7840bb5af4807"), __wbg_waitUntil_dd14bc39c5034fc9: /* @__PURE__ */ __name(function() {
    return c(function(t, e) {
      r(t).waitUntil(r(e));
    }, arguments);
  }, "__wbg_waitUntil_dd14bc39c5034fc9"), __wbg_warn_c4e0780980765a86: /* @__PURE__ */ __name(function(t) {
    console.warn(r(t));
  }, "__wbg_warn_c4e0780980765a86"), __wbg_webSocket_09cce4e1ce833134: /* @__PURE__ */ __name(function() {
    return c(function(t) {
      let e = r(t).webSocket;
      return w(e) ? 0 : _(e);
    }, arguments);
  }, "__wbg_webSocket_09cce4e1ce833134"), __wbg_writable_ba649cddfe4b0a3d: /* @__PURE__ */ __name(function(t) {
    let e = r(t).writable;
    return _(e);
  }, "__wbg_writable_ba649cddfe4b0a3d"), __wbindgen_cast_0000000000000001: /* @__PURE__ */ __name(function(t, e) {
    let n = D(t, e, bt);
    return _(n);
  }, "__wbindgen_cast_0000000000000001"), __wbindgen_cast_0000000000000002: /* @__PURE__ */ __name(function(t, e) {
    let n = D(t, e, ft);
    return _(n);
  }, "__wbindgen_cast_0000000000000002"), __wbindgen_cast_0000000000000003: /* @__PURE__ */ __name(function(t, e) {
    let n = D(t, e, at);
    return _(n);
  }, "__wbindgen_cast_0000000000000003"), __wbindgen_cast_0000000000000004: /* @__PURE__ */ __name(function(t) {
    return _(t);
  }, "__wbindgen_cast_0000000000000004"), __wbindgen_cast_0000000000000005: /* @__PURE__ */ __name(function(t) {
    return _(t);
  }, "__wbindgen_cast_0000000000000005"), __wbindgen_cast_0000000000000006: /* @__PURE__ */ __name(function(t, e) {
    let n = F(t, e);
    return _(n);
  }, "__wbindgen_cast_0000000000000006"), __wbindgen_cast_0000000000000007: /* @__PURE__ */ __name(function(t, e) {
    let n = p(t, e);
    return _(n);
  }, "__wbindgen_cast_0000000000000007"), __wbindgen_cast_0000000000000008: /* @__PURE__ */ __name(function(t) {
    let e = BigInt.asUintN(64, t);
    return _(e);
  }, "__wbindgen_cast_0000000000000008"), __wbindgen_object_clone_ref: /* @__PURE__ */ __name(function(t) {
    let e = r(t);
    return _(e);
  }, "__wbindgen_object_clone_ref"), __wbindgen_object_drop_ref: /* @__PURE__ */ __name(function(t) {
    d(t);
  }, "__wbindgen_object_drop_ref") } };
}
__name(st, "st");
function a() {
  if (ct) {
    H();
    return;
  }
}
__name(a, "a");
function at(i3, t) {
  a(), s.__wasm_bindgen_func_elem_7793(i3, t);
}
__name(at, "at");
function ft(i3, t, e) {
  a(), s.__wasm_bindgen_func_elem_7314(i3, t, _(e));
}
__name(ft, "ft");
function bt(i3, t, e) {
  try {
    let u = s.__wbindgen_add_to_stack_pointer(-16);
    a(), s.__wasm_bindgen_func_elem_3831(u, i3, t, _(e));
    var n = b().getInt32(u + 0, true), o = b().getInt32(u + 4, true);
    if (o) throw d(n);
  } finally {
    s.__wbindgen_add_to_stack_pointer(16);
  }
}
__name(bt, "bt");
function gt(i3, t, e, n) {
  a(), s.__wasm_bindgen_func_elem_3870(i3, t, _(e), _(n));
}
__name(gt, "gt");
var dt = ["bytes"];
var wt = ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"];
var lt = ["follow", "error", "manual"];
var f = 0;
var pt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_containerstartupoptions_free(i3, 1);
});
var ht = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_intounderlyingbytesource_free(i3, 1);
});
var mt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_intounderlyingsink_free(i3, 1);
});
var Q = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_intounderlyingsource_free(i3, 1);
});
var X = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_minifyconfig_free(i3, 1);
});
var Y = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_pluginroomlog_free(i3, 1);
});
var yt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_r2range_free(i3, 1);
});
var Z = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: i3, instance: t }) => {
  t === f && s.__wbg_userinbox_free(i3, 1);
});
function _(i3) {
  E === x.length && x.push(x.length + 1);
  let t = E;
  return E = x[t], x[t] = i3, t;
}
__name(_, "_");
var tt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry((i3) => {
  i3.instance === f && s.__wbindgen_export5(i3.a, i3.b);
});
function N(i3) {
  let t = typeof i3;
  if (t == "number" || t == "boolean" || i3 == null) return `${i3}`;
  if (t == "string") return `"${i3}"`;
  if (t == "symbol") {
    let o = i3.description;
    return o == null ? "Symbol" : `Symbol(${o})`;
  }
  if (t == "function") {
    let o = i3.name;
    return typeof o == "string" && o.length > 0 ? `Function(${o})` : "Function";
  }
  if (Array.isArray(i3)) {
    let o = i3.length, u = "[";
    o > 0 && (u += N(i3[0]));
    for (let g = 1; g < o; g++) u += ", " + N(i3[g]);
    return u += "]", u;
  }
  let e = /\[object ([^\]]+)\]/.exec(toString.call(i3)), n;
  if (e && e.length > 1) n = e[1];
  else return toString.call(i3);
  if (n == "Object") try {
    return "Object(" + JSON.stringify(i3) + ")";
  } catch {
    return "Object";
  }
  return i3 instanceof Error ? `${i3.name}: ${i3.message}
${i3.stack}` : n;
}
__name(N, "N");
function xt(i3) {
  i3 < 1028 || (x[i3] = E, E = i3);
}
__name(xt, "xt");
function It(i3, t) {
  i3 = i3 >>> 0;
  let e = b(), n = [];
  for (let o = i3; o < i3 + 4 * t; o += 4) n.push(d(e.getUint32(o, true)));
  return n;
}
__name(It, "It");
function F(i3, t) {
  return i3 = i3 >>> 0, C().subarray(i3 / 1, i3 / 1 + t);
}
__name(F, "F");
var S = null;
function b() {
  return (S === null || S.buffer.detached === true || S.buffer.detached === void 0 && S.buffer !== s.memory.buffer) && (S = new DataView(s.memory.buffer)), S;
}
__name(b, "b");
function p(i3, t) {
  return vt(i3 >>> 0, t);
}
__name(p, "p");
var M = null;
function C() {
  return (M === null || M.byteLength === 0) && (M = new Uint8Array(s.memory.buffer)), M;
}
__name(C, "C");
function r(i3) {
  return x[i3];
}
__name(r, "r");
function c(i3, t) {
  try {
    return i3.apply(this, t);
  } catch (e) {
    s.__wbindgen_export3(_(e));
  }
}
__name(c, "c");
var x = new Array(1024).fill(void 0);
x.push(void 0, null, true, false);
var E = x.length;
function w(i3) {
  return i3 == null;
}
__name(w, "w");
function D(i3, t, e) {
  let n = { a: i3, b: t, cnt: 1, instance: f }, o = /* @__PURE__ */ __name((...u) => {
    if (n.instance !== f) throw new Error("Cannot invoke closure from previous WASM instance");
    n.cnt++;
    let g = n.a;
    n.a = 0;
    try {
      return e(g, n.b, ...u);
    } finally {
      n.a = g, o._wbg_cb_unref();
    }
  }, "o");
  return o._wbg_cb_unref = () => {
    --n.cnt === 0 && (s.__wbindgen_export5(n.a, n.b), n.a = 0, tt.unregister(n));
  }, tt.register(o, n, n), o;
}
__name(D, "D");
function V(i3, t) {
  let e = t(i3.length * 4, 4) >>> 0, n = b();
  for (let o = 0; o < i3.length; o++) n.setUint32(e + 4 * o, _(i3[o]), true);
  return h = i3.length, e;
}
__name(V, "V");
function m(i3, t, e) {
  if (e === void 0) {
    let l = L.encode(i3), y = t(l.length, 1) >>> 0;
    return C().subarray(y, y + l.length).set(l), h = l.length, y;
  }
  let n = i3.length, o = t(n, 1) >>> 0, u = C(), g = 0;
  for (; g < n; g++) {
    let l = i3.charCodeAt(g);
    if (l > 127) break;
    u[o + g] = l;
  }
  if (g !== n) {
    g !== 0 && (i3 = i3.slice(g)), o = e(o, n, n = g + i3.length * 3, 1) >>> 0;
    let l = C().subarray(o + g, o + n), y = L.encodeInto(i3, l);
    g += y.written, o = e(o, n, g, 1) >>> 0;
  }
  return h = g, o;
}
__name(m, "m");
var ct = false;
function d(i3) {
  let t = r(i3);
  return xt(i3), t;
}
__name(d, "d");
var ut = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
ut.decode();
function vt(i3, t) {
  return ut.decode(C().subarray(i3, i3 + t));
}
__name(vt, "vt");
var L = new TextEncoder();
"encodeInto" in L || (L.encodeInto = function(i3, t) {
  let e = L.encode(i3);
  return t.set(e), { read: i3.length, written: e.length };
});
var h = 0;
var $ = new WebAssembly.Instance(et, st());
var s = $.exports;
s.__wbindgen_start();
Error.stackTraceLimit = 100;
var v = nt();
function J() {
  v.criticalError && (console.log("Reinitializing Wasm application"), H(), v.criticalError = false, v.instanceId++);
}
__name(J, "J");
addEventListener("error", (i3) => {
  G(i3.error);
});
function G(i3) {
  i3 instanceof WebAssembly.RuntimeError && (console.error("Critical", i3), v.criticalError = true);
}
__name(G, "G");
var k = class extends Et {
  static {
    __name(this, "k");
  }
};
k.prototype.fetch = function(t) {
  return rt.call(this, t, this.env, this.ctx);
};
k.prototype.init = _t;
k.prototype.scheduled = function(t) {
  return ot.call(this, t, this.env, this.ctx);
};
k.prototype.start = it;
var jt = { set: /* @__PURE__ */ __name((i3, t, e, n) => Reflect.set(i3.instance, t, e, n), "set"), has: /* @__PURE__ */ __name((i3, t) => Reflect.has(i3.instance, t), "has"), deleteProperty: /* @__PURE__ */ __name((i3, t) => Reflect.deleteProperty(i3.instance, t), "deleteProperty"), apply: /* @__PURE__ */ __name((i3, t, e) => Reflect.apply(i3.instance, t, e), "apply"), construct: /* @__PURE__ */ __name((i3, t, e) => Reflect.construct(i3.instance, t, e), "construct"), getPrototypeOf: /* @__PURE__ */ __name((i3) => Reflect.getPrototypeOf(i3.instance), "getPrototypeOf"), setPrototypeOf: /* @__PURE__ */ __name((i3, t) => Reflect.setPrototypeOf(i3.instance, t), "setPrototypeOf"), isExtensible: /* @__PURE__ */ __name((i3) => Reflect.isExtensible(i3.instance), "isExtensible"), preventExtensions: /* @__PURE__ */ __name((i3) => Reflect.preventExtensions(i3.instance), "preventExtensions"), getOwnPropertyDescriptor: /* @__PURE__ */ __name((i3, t) => Reflect.getOwnPropertyDescriptor(i3.instance, t), "getOwnPropertyDescriptor"), defineProperty: /* @__PURE__ */ __name((i3, t, e) => Reflect.defineProperty(i3.instance, t, e), "defineProperty"), ownKeys: /* @__PURE__ */ __name((i3) => Reflect.ownKeys(i3.instance), "ownKeys") };
var I = { construct(i3, t, e) {
  try {
    J();
    let n = { instance: Reflect.construct(i3, t, e), instanceId: v.instanceId, ctor: i3, args: t, newTarget: e };
    return new Proxy(n, { ...jt, get(o, u, g) {
      o.instanceId !== v.instanceId && (o.instance = Reflect.construct(o.ctor, o.args, o.newTarget), o.instanceId = v.instanceId);
      let l = Reflect.get(o.instance, u, g);
      return typeof l != "function" ? l : l.constructor === Function ? new Proxy(l, { apply(y, q, B) {
        J();
        try {
          return y.apply(q, B);
        } catch (U) {
          throw G(U), U;
        }
      } }) : new Proxy(l, { async apply(y, q, B) {
        J();
        try {
          return await y.apply(q, B);
        } catch (U) {
          throw G(U), U;
        }
      } });
    } });
  } catch (n) {
    throw v.criticalError = true, n;
  }
} };
var At = new Proxy(k, I);
var zt = new Proxy(W, I);
var Ot = new Proxy(A, I);
var Pt = new Proxy(z, I);
var Tt = new Proxy(j, I);
var Ut = new Proxy(R, I);
var Mt = new Proxy(O, I);
var Ct = new Proxy(P, I);
var Lt = new Proxy(T, I);

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

// .wrangler/tmp/bundle-F4sdXQ/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = At;

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

// .wrangler/tmp/bundle-F4sdXQ/middleware-loader.entry.ts
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
  zt as ContainerStartupOptions,
  Ot as IntoUnderlyingByteSource,
  Pt as IntoUnderlyingSink,
  Tt as IntoUnderlyingSource,
  Ut as MinifyConfig,
  Mt as PluginRoomLog,
  Ct as R2Range,
  Lt as UserInbox,
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=shim.js.map

//# sourceURL=file:///home/hasan/.cache/gecici/sezi-workerd.ZoB1bb/relay/.wrangler/tmp/dev-QJ25HP/shim.js