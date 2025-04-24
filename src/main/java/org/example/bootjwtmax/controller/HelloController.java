package org.example.bootjwtmax.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController // 이 클래스가 REST API 컨트롤러임을 명시
@RequestMapping("/api/test") // 이 컨트롤러의 기본 경로는 /api/test
@Tag(name = "Greeting API", description = "간단한 인사말을 반환하는 엔드포인트") // Swagger 문서용 태그
@SecurityScheme(
        name = "bearerAuth", // 인증 방식 이름(아래에서 참조)
        type = SecuritySchemeType.HTTP, // HTTP 기반 인증
        scheme = "bearer", // Bearer 타입(토큰 기반)
        bearerFormat = "JWT", // JWT 포맷
        description = "JWT Bearer token" // Swagger 문서에 표시될 설명
)
public class HelloController {

    @Operation( // Swagger 문서에서 이 API의 정보를 정의
            summary = "Hello World 메시지 가져오기", // 간단 설명
            description = "이 엔드포인트는 'Hello World' 문자열을 반환합니다.", // 상세 설명
            security = @SecurityRequirement(name = "bearerAuth") // JWT 인증 필요함을 명시
    )
    @ApiResponses(value = { // 가능한 응답 코드 목록
            @ApiResponse(responseCode = "200", description = "성공적으로 메시지 반환")
    })
    @GetMapping // GET /api/test
    public String hello() {
        return "Hello World"; // 문자열 응답
    }

    // JWT 인증이 실제로 동작하는지 확인할 수 있는 엔드포인트
    @Operation(
            security = @SecurityRequirement(name = "bearerAuth") // JWT 인증 필요
    )
    @GetMapping("/me") // GET /api/test/me
    public String me(Authentication authentication) {
        // Authentication 객체는 인증된 사용자 정보를 담고 있음
        // authentication.getName() : username
        // authentication.getAuthorities() : 권한 목록
        return "%s, %s".formatted(authentication.getName(), authentication.getAuthorities());
    }
}
