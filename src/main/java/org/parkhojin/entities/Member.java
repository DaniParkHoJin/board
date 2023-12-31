package org.parkhojin.entities;

import lombok.Data;
import org.parkhojin.commons.constants.MemberType;
import org.springframework.data.annotation.Id;

import java.time.LocalDateTime;

@Data
public class Member {

    @Id
    private Long userNo;

    private String email;

    private String password;

    private String userNm;

    private String mobile;

    private MemberType mytpe = MemberType.USER;

    private LocalDateTime regDt;
    private LocalDateTime modDt;
}
