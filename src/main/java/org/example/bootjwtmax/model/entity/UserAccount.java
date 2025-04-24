package org.example.bootjwtmax.model.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

@Entity // JPA 엔티티(테이블 매핑)
@Data // Lombok: getter/setter, toString 등 자동 생성
public class UserAccount {
    @Id // 기본키(PK) 지정
    @GeneratedValue(strategy = GenerationType.UUID) // UUID 자동 생성
    private String id;

    @Column(nullable = false, unique = true) // Not null, 유니크 제약조건
    private String username; // 아이디

    @Column(nullable = false) // Not null
    private String password; // 암호화된 비밀번호

    @CreationTimestamp // 엔티티 생성 시 자동으로 현재 시간 저장
    private ZonedDateTime createdAt = ZonedDateTime.now(ZoneOffset.UTC);

    @Column(nullable = false)
    private String role; // 권한 (예: USER, ADMIN)
}
