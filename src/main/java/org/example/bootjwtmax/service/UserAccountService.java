package org.example.bootjwtmax.service;

import org.apache.coyote.BadRequestException;
import org.example.bootjwtmax.model.dto.UserAccountJoinDTO;

public interface UserAccountService {
    void join(UserAccountJoinDTO dto) throws BadRequestException;
}
