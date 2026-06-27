"""Shield — model-bagimsiz guvenlik kalkani.

Herhangi bir LLM fonksiyonunu (prompt:str -> str) sarar:
  1) Girdiyi input-dedektorlerden gecirir; bloklanirsa LLM'i HIC cagirmaz.
  2) Izin varsa LLM'i cagirir.
  3) Ciktiyi output-dedektorlerden gecirir; bloklanirsa cikti yerine gerekce doner.

Her karar bir ShieldResult.explain() ile "neden" aciklamasi tasir.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from reasongate import policy
from reasongate.audit import AuditHook, safe_emit
from reasongate.detectors.base import Detector
from reasongate.detectors import (InjectionDetector, LeakageDetector,
                                 NormalizationDetector)
from reasongate.detectors.indirect import IndirectInjectionDetector
from reasongate.detectors.provenance import ProvenanceDetector
from reasongate.types import Segment, ShieldResult


class Shield:
    def __init__(self,
                 input_detectors: Optional[List[Detector]] = None,
                 output_detectors: Optional[List[Detector]] = None,
                 context_detectors: Optional[List[Detector]] = None,
                 block_threshold: float = 0.8,
                 flag_threshold: float = 0.5,
                 provenance_cap: float = 0.5,
                 audit_hook: Optional[AuditHook] = None):
        # Varsayilan: injection + obfuscation (gizleme) kalkani birlikte.
        # NormalizationDetector regex'i atlatmak icin gizlenmis saldirilari
        # (zero-width, homoglyph, leetspeak, aralikli harf) yakalar.
        self.input_detectors = input_detectors if input_detectors is not None else [
            InjectionDetector(), NormalizationDetector()]
        self.output_detectors = output_detectors if output_detectors is not None else [LeakageDetector()]
        # Context (RAG/tool) dedektorleri: dolayli enjeksiyon icin.
        self.context_detectors = context_detectors if context_detectors is not None else [
            IndirectInjectionDetector()]
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        # Provenance: SADECE Segment-API'ye opt-in edilince calisir (asagida).
        # Plain str/list[str] -> provenance KAPALI -> eski davranis birebir.
        # CAP karar-seviyesi karma-guven FPR'den kalibre edilecek (su an parametre).
        self._provenance = ProvenanceDetector(cap=provenance_cap)
        # Denetim kancasi: her karar burdan yayinlanir (varsayilan: yok).
        # Bkz. reasongate.audit (log_sink / file_sink) — kurumsal SIEM
        # sink'leri bu kanca uzerine private katmanda kurulur.
        self.audit_hook = audit_hook

    def _emit(self, result: ShieldResult) -> ShieldResult:
        """Kararı denetim kancasina yollar (ayarliysa) ve aynen geri doner.
        Denetim yayini guvenlik kararini ASLA bozmaz (bkz. audit.safe_emit)."""
        if self.audit_hook is not None:
            safe_emit(self.audit_hook, result)
        return result

    def scan_input(self, prompt: str, *, _emit: bool = True) -> ShieldResult:
        dets = [d.scan(prompt) for d in self.input_detectors]
        action, _ = policy.decide(dets, self.block_threshold, self.flag_threshold)
        res = ShieldResult(action=action, stage="input", detections=dets)
        return self._emit(res) if _emit else res

    def scan_context(self, segments, *, _emit: bool = True) -> ShieldResult:
        """Retrieve edilen icerigi (RAG dokumani, tool ciktisi, web sayfasi)
        dolayli-enjeksiyona karsi tarar.

        segments: str | list[str] | Segment | list[Segment]. Segment GECILIRSE
        provenance dedektoru aktiflesir (koken-temelli prior); plain str ise
        KAPALI kalir (eski davranis birebir korunur — korunan yol risksiz)."""
        if isinstance(segments, (str, Segment)):
            segments = [segments]
        segments = segments or []
        # Provenance YALNIZ en az bir Segment metadata'si verilince acilir.
        provenance_on = any(isinstance(s, Segment) for s in segments)
        dets = []
        for i, raw in enumerate(segments):
            seg = raw if isinstance(raw, Segment) else None
            text = seg.text if seg is not None else raw
            for d in self.context_detectors:
                det = d.scan(text)
                if det.matches:                      # sadece sinyal taşıyanları raporla
                    det.reason = f"[parca {i}] " + det.reason
                    dets.append(det)
            if provenance_on and seg is not None:
                pdet = self._provenance.scan_segment(seg)
                if pdet.matches:
                    pdet.reason = f"[parca {i}] " + pdet.reason
                    dets.append(pdet)
        if not dets:
            res = ShieldResult(action="allow", stage="context", detections=[])
            return self._emit(res) if _emit else res
        action, _ = policy.decide(dets, self.block_threshold, self.flag_threshold)
        res = ShieldResult(action=action, stage="context", detections=dets)
        return self._emit(res) if _emit else res

    def scan_output(self, text: str, *, _emit: bool = True) -> ShieldResult:
        dets = [d.scan(text) for d in self.output_detectors]
        action, _ = policy.decide(dets, self.block_threshold, self.flag_threshold)
        res = ShieldResult(action=action, stage="output", detections=dets, output=text)
        return self._emit(res) if _emit else res

    def protect(self, prompt: str, llm_fn: Callable[[str], str],
                context=None) -> ShieldResult:
        """Tek cagri: girdi (+context) tara -> (gerekirse) LLM cagir -> cikti tara.

        context verildiyse (RAG/tool icerigi), LLM cagrilmadan once dolayli
        enjeksiyona karsi taranir; bloklanirsa LLM HIC cagrilmaz.
        """
        # Ic taramalar tek tek YAYINLANMAZ (_emit=False); protect TEK bir
        # nihai karar yayinlar, boylece bir istek = bir denetim kaydi.
        inp = self.scan_input(prompt, _emit=False)
        if inp.action == "block":
            return self._emit(inp)  # LLM hic cagrilmadi

        ctx = self.scan_context(context, _emit=False) if context is not None else None
        if ctx is not None and ctx.action == "block":
            return self._emit(ctx)  # zehirli context -> LLM hic cagrilmadi

        raw = llm_fn(prompt)
        out = self.scan_output(raw, _emit=False)
        # girdi/context 'flag' ise ve cikti temizse, flag bilgisini koru
        upstream = [r for r in (inp, ctx) if r is not None and r.action == "flag"]
        if upstream and out.action == "allow":
            out.action = "flag"
            for r in upstream:
                out.detections = r.detections + out.detections
        return self._emit(out)

    def guard(self, llm_fn: Callable[[str], str]) -> Callable[[str], ShieldResult]:
        """Herhangi bir LLM fonksiyonunu korumali bir surumune cevirir."""
        def wrapped(prompt: str, context=None) -> ShieldResult:
            return self.protect(prompt, llm_fn, context=context)
        return wrapped
