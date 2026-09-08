from dataclasses import dataclass, field


@dataclass
class AttackSurface:
    """프로파일러가 추출한 단일 공격 표면."""
    surface_type:  str   # 'form_field' | 'url_param' | 'hidden_param' | 'api_field'
    url:           str
    method:        str   # GET | POST | PUT | PATCH
    param:         str
    page:          dict  # 원본 page 레코드 (tech_stack 등 컨텍스트)
    response_type: str       = 'unknown'  # 'html' | 'json' | 'unknown'
    blind:         bool|None = None       # True=블라인드, False=reflected, None=미확정
    login_id:      str|None  = None
    login_pw:      str|None  = None
    extra:         dict      = field(default_factory=dict)
    # extra 키:
    #   hints          : {vuln_type: weight}
    #   enctype        : 'application/json' | 'application/x-www-form-urlencoded'
    #   all_params     : 동반 전송할 다른 필드명 목록
    #   proxy_template : JSON 프록시 폼 descriptor
    #   proxy_field    : JSON 프록시 hidden input 이름


@dataclass
class VulnResult:
    """strategy가 반환하는 단일 취약점 결과."""
    surface:   AttackSurface
    vuln_type: str   # 'SSTI' | 'SQLi' | 'XSS' | ...
    severity:  str   # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO'
    payload:   str
    evidence:  str   # 응답에서 취약점을 확인한 근거
    detail:    dict = field(default_factory=dict)
