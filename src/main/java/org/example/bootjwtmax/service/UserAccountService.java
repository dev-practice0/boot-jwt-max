package org.example.bootjwtmax.service;

import org.apache.coyote.BadRequestException;
import org.example.bootjwtmax.model.dto.UserAccountRequestDTO;

public interface UserAccountService {
    void join(UserAccountRequestDTO dto) throws BadRequestException;
}
