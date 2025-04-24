package org.example.bootjwtmax.service;

import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.example.bootjwtmax.model.dto.UserAccountJoinDTO;
import org.example.bootjwtmax.model.entity.UserAccount;
import org.example.bootjwtmax.model.repository.UserAccountRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserAccountServiceImpl implements UserAccountService {
    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void join(UserAccountJoinDTO dto) throws BadRequestException {
        if (dto.username().isEmpty() || dto.password().isEmpty()) {
            throw new BadRequestException("비어 있는 항목이 있습니다");
        }
        UserAccount userAccount = new UserAccount();
        userAccount.setUsername(dto.username());
        userAccount.setPassword(
            passwordEncoder.encode(dto.password())
        );
        try {
            userAccountRepository.save(userAccount);
        } catch (DataIntegrityViolationException ex) {
            throw new BadRequestException("중복된 Username");
            // 내가 새로운 거 만들어도 됨
        }
    }
}
