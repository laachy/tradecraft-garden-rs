package crystalpalace.btf.pass.mutate;

import crystalpalace.btf.*;
import crystalpalace.btf.Code;
import crystalpalace.btf.pass.*;
import crystalpalace.coff.*;
import crystalpalace.util.*;

import java.util.*;
import java.io.*;

import com.github.icedland.iced.x86.*;
import com.github.icedland.iced.x86.asm.*;
import com.github.icedland.iced.x86.enc.*;
import com.github.icedland.iced.x86.dec.*;
import com.github.icedland.iced.x86.fmt.*;
import com.github.icedland.iced.x86.fmt.gas.*;

public class CallWalk {
	protected COFFObject          object  = null;
	protected Set                 touched = new HashSet();
	protected Map                 funcs   = null;
	protected Code                code    = null;

	public CallWalk(Code code) {
		this.code   = code;
		this.object = code.getObject();
	}

	/*
	 * This is our x64 call analysis, the purpose of this section is to walk our code (using a specific starting
	 * function), and determine which functions are used vs. not.
	 */
	protected void walk_x64(String function) {
		/* our instructions of interest */
		Set x64insts = new HashSet();
		x64insts.add("LEA r64, m");
		x64insts.add("MOV r64, r/m64");
		x64insts.add("CALL r/m64");
    x64insts.add("JMP r/m64");

		/* if we're walking the function, it's referenced/called and we want to keep it */
		touched.add(function);

		/* start walking instruction by instruction */
		Iterator i = ( (List)funcs.get(function) ).iterator();
		while (i.hasNext()) {
			Instruction inst = (Instruction)i.next();

			if ( inst.isCallNear() ) {
				Symbol temp = code.getLabel( inst.getMemoryDisplacement32() );
				if (temp != null && !touched.contains( temp.getName() ))
					walk_x64( temp.getName() );
			}
			else if (inst.isIPRelativeMemoryOperand()) {
				if (x64insts.contains(inst.getOpCode().toInstructionString())) {
					Symbol temp = code.getLabel( inst.getMemoryDisplacement32() );
					if (temp != null && !touched.contains( temp.getName() ))
						walk_x64( temp.getName() );
				}
			}

      if (inst.getFlowControl() == FlowControl.UNCONDITIONAL_BRANCH) {
        int op0 = inst.getOp0Kind();
        if (op0 == OpKind.NEAR_BRANCH64 || op0 == OpKind.NEAR_BRANCH32) {
          long targetIp = inst.getNearBranchTarget(); // iced-x86 Java API

          // Depending on your Code.getLabel() signature you might need a cast:
          // Symbol temp = code.getLabel((int)targetIp);
          Symbol temp = code.getLabel(targetIp);

          if (temp != null && !touched.contains(temp.getName())) {
              walk_x64(temp.getName());
          }
        }
      }

			/* handle .refptr labels as a special case */
			Relocation r = code.getRelocation(inst);
			if (r != null && r.getSymbolName().startsWith(".refptr.")) {
				String symb = r.getSymbolName().substring(8);
				Symbol temp = object.getSymbol(symb);
				if (temp != null && ".text".equals(temp.getSection().getName()) && !touched.contains(temp.getName())) {
					walk_x64( temp.getName() );
				}
			}
		}
	}

	/*
	 * This is our x86 call analysis, the purpose of this section is to walk our code (using a specific starting
	 * function), and determine which functions are used vs. not.
	 */
	protected void walk_x86(String function) {
		/* if we're walking the function, it's referenced/called and we want to keep it */
		touched.add(function);

		/* start walking instruction by instruction */
		Iterator i = ( (List)funcs.get(function) ).iterator();
		while (i.hasNext()) {
			Instruction inst = (Instruction)i.next();

			/* if this is an instruction that touches our local label, we want to get that label
			 * and walk that function */
			if ( inst.isCallNear() ) {
				Symbol temp = code.getLabel( inst.getMemoryDisplacement32() );
				if (temp != null && !touched.contains( temp.getName() ))
					walk_x86( temp.getName() );
			}

			/* check for a relocation associated with the label */
			Relocation r = code.getRelocation(inst);
			if (r != null && ".text".equals(r.getSymbolName())) {
				Symbol temp = code.getLabel( r.getOffsetAsLong() );
				if (temp != null && !touched.contains( temp.getName() ))
					walk_x86( temp.getName() );
			}
			/* same type of thing as the x64 .refptr issue... we have a relocation for a local symbol... we need to walk it */
			else if (r != null) {
				Symbol temp = object.getSymbol(r.getSymbolName());
				if (temp != null && temp.getSection() != null && ".text".equals(temp.getSection().getName()) && !touched.contains(temp.getName())) {
					walk_x86( temp.getName() );
				}
			}
		}
	}
}
