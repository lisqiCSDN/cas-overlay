package com.dspj.authc.handler;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.InvalidLoginLocationException;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import java.sql.*;
import java.util.Collections;

/**
 * @ClassName: MyAuthenticationHandler
 * @Date: 2019/5/10
 * @describe:
 */
public class MyAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    public MyAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    /**
     * 用于判断用户的Credential(换而言之，就是登录信息)，是否是俺能处理的
     * 就是有可能是，子站点的登录信息中不止有用户名密码等信息，还有部门信息的情况
     */
    @Override
    public boolean supports(Credential credential) {
        //判断传递过来的Credential 是否是自己能处理的类型
        return credential instanceof UsernamePasswordCredential;
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws GeneralSecurityException {
        UsernamePasswordCredential usernamePasswordCredentia = (UsernamePasswordCredential) credential;

        //获取传递过来的用户名和密码
        String username = usernamePasswordCredentia.getUsername();
        String password = usernamePasswordCredentia.getPassword();
//        DriverManagerDataSource d=new DriverManagerDataSource();
//        d.setDriverClassName("com.mysql.jdbc.Driver");
//        d.setUrl("jdbc:mysql://127.0.0.1:3306/test");
//        d.setUsername("root");
//        d.setPassword("root");
//        JdbcTemplate template=new JdbcTemplate();
//        template.setDataSource(d);
        Connection conn = null;
        try {
            Class.forName("oracle.jdbc.OracleDriver");

            //直接是原生的数据库配置啊
            String url = "jdbc:oracle:thin:@192.168.1.91:1521:test";
            String user = "root";
            String pass = "123456";

            conn = DriverManager.getConnection(url,user, pass);

            //查询语句
            String sql = "SELECT * FROM SYS_USERS where USER_NAME=? AND PASSWORD = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username);
            ps.setString(2, password);

            ResultSet rs = ps.executeQuery();

            if(rs.next()) {
                //允许登录，并且通过this.principalFactory.createPrincipal来返回用户属性
                return createHandlerResult(credential, this.principalFactory.createPrincipal(username, Collections.emptyMap()), null);
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }finally {
            if(conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
        //当是admin用户的情况，直接就登录了，谁叫他是admin用户呢
        if(username.startsWith("admin")) {
            //直接返回去了
            return createHandlerResult(credential, this.principalFactory.createPrincipal(username, Collections.emptyMap()), null);
        }else if (username.startsWith("lock")) {
            //用户锁定
            throw new AccountLockedException();
        } else if (username.startsWith("disable")) {
            //用户禁用
            throw new AccountDisabledException();
        } else if (username.startsWith("invali")) {
            //禁止登录该工作站登录
            throw new InvalidLoginLocationException();
        } else if (username.startsWith("passorwd")) {
            //密码错误
            throw new FailedLoginException();
        } else if (username.startsWith("account")) {
            //账号错误
            throw new AccountLockedException();
        }
        return null;
    }
}
