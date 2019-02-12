package com.yubico.objects.yhconcepts;

/**
 * Class representing different concepts known to the device
 */
public class YHConcept {

    private final Object id;
    private final String name;

    /**
     * @param id   The concept ID
     * @param name The concept name
     */
    public YHConcept(final Object id, final String name) {
        this.id = id;
        this.name = name;
    }

    /**
     * @return The concept's ID
     */
    protected Object getId() {
        return id;
    }

    /**
     * @return The concept's name
     */
    public String getName() {
        return name;
    }

    /**
     * Compares two concept objects
     *
     * @param a A YHConcept object
     * @param b Another YHConcept object
     * @return True of the two objects are of the same type and whose IDs are equals. False otherwise
     */
    public static boolean equals(final YHConcept a, final YHConcept b) {
        if (!a.getClass().equals(b.getClass())) {
            return false;
        }
        return a.getId().equals(b.getId());
    }

}
