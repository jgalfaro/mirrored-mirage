package tests.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import util.StringField;

public class StringFieldTest {

	@Test public void constructor1() {
		StringField v = new StringField("payload1");
		assertEquals("payload1", v.getValue());
	}
	
	@Test public void constructor2() {
		StringField v = new StringField("");
		assertEquals("", v.getValue());
		assertNotSame(StringField.EMPTY, v);
	}
	
	@Test public void constructor3() {
		StringField empty = StringField.EMPTY;
		assertEquals("", empty.getValue());
		StringField v = new StringField("");
		assertNotSame(empty, v);
	}
	
	@Test public void defaultAny() {
		StringField v = new StringField("payload");
		assertEquals(StringField.ANY, v.getDefaultAny());
	}
	
	@Test public void equals1() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload1");
		assertEquals(a, b);
	}
	
	@Test public void equals2() {
		StringField a = StringField.ANY;
		StringField b = StringField.ANY;
		assertEquals(a, b);
	}
	
	@Test public void equals3() {
		StringField a = StringField.EMPTY;
		StringField b = StringField.EMPTY;
		assertEquals(a, b);
	}

	@Test public void equals4() {
		StringField a = StringField.EMPTY;
		StringField b = new StringField("");
		assertNotSame(a, b);
	}

	@Test public void equals5() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload2");
		assertFalse(a.equals(b));
	}
	
	@Test public void inter1() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload1");
		StringField res = new StringField("payload1");
		assertEquals(res, a.inter(b));
	}

	@Test public void inter2() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload2");
		StringField res = StringField.EMPTY;
		assertEquals(res, b.inter(a));
	}
	
	@Test public void inter3() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload2");
		StringField res = StringField.EMPTY;
		assertEquals(res, a.inter(b));
	}

	@Test public void inter4() {
		StringField a = new StringField("payload1");
		StringField b = StringField.EMPTY;
		StringField res = StringField.EMPTY;
		assertEquals(res, b.inter(a));
	}
	
	@Test public void inter5() {
		StringField a = new StringField("payload1");
		StringField b = StringField.EMPTY;
		StringField res = StringField.EMPTY;
		assertEquals(res, a.inter(b));
	}

	@Test public void inter6() {
		StringField a = new StringField("payload1");
		StringField b = StringField.ANY;
		StringField res = new StringField("payload1");
		assertEquals(res, b.inter(a));
	}
	
	@Test public void inter7() {
		StringField a = new StringField("payload1");
		StringField b = StringField.ANY;
		StringField res = new StringField("payload1");
		assertEquals(res, a.inter(b));
	}

	@Test public void inter8() {
		StringField a = StringField.ANY;
		StringField b = StringField.ANY;
		StringField res = StringField.ANY;
		assertEquals(res, a.inter(b));
	}

	@Test public void minus1() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload1");
		List<StringField> res = new ArrayList<StringField>();
		assertEquals(res, a.minus(b));
	}

	@Test public void minus2() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload2");
		List<StringField> res = new ArrayList<StringField>();
		res.add(new StringField("payload2"));
		assertEquals(res, b.minus(a));
	}
	
	@Test public void minus3() {
		StringField a = new StringField("payload1");
		StringField b = new StringField("payload2");
		List<StringField> res = new ArrayList<StringField>();
		res.add(new StringField("payload1"));
		assertEquals(res, a.minus(b));
	}

	@Test public void minus4() {
		StringField a = new StringField("payload1");
		StringField b = StringField.EMPTY;
		List<StringField> res = new ArrayList<StringField>();
		res.add(StringField.EMPTY);
		assertEquals(res, b.minus(a));
	}
	
	@Test public void minus5() {
		StringField a = new StringField("payload1");
		StringField b = StringField.EMPTY;
		List<StringField> res = new ArrayList<StringField>();
		res.add(new StringField("payload1"));
		assertEquals(res, a.minus(b));
	}

	@Test public void minus6() {
		StringField a = new StringField("payload1");
		StringField b = StringField.ANY;
		List<StringField> res = new ArrayList<StringField>();
		res.add(StringField.ANY);
		assertEquals(res, b.minus(a));
	}
	
	@Test public void minus7() {
		StringField a = new StringField("payload1");
		StringField b = StringField.ANY;
		List<StringField> res = new ArrayList<StringField>();
		assertEquals(res, a.minus(b));
	}

	@Test public void minus8() {
		StringField a = StringField.ANY;
		StringField b = StringField.ANY;
		List<StringField> res = new ArrayList<StringField>();
		assertEquals(res, a.minus(b));
	}
	
}
