using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Framework;
using Security.Framework.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace Security.Framwork.Test.Entities
{
    [TestClass]
    public class JwtTest
    {
       
        [TestMethod]
        public void ConstructorTest_StringFull()
        {
            //Arrange
            String token = "Teste;teste;teste";
            //Act
            Jwt jwt = new Jwt(token);
            //Assert
            
        }
    }
}
